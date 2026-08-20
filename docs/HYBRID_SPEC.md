# geryon Hybrid Protocol Specification

**Version:** 1.0 (ACCEPTED)
**Protocol version:** 1
**Date:** July 2026 (v1.0 Accepted 2026-08-10)
**Status:** v1.0 Accepted - NORMATIVE for the hybrid suites. All open
items resolved; the formal results are summarized in §10.9. Changes now
follow the decisions register (docs/decisions/) spec-first.

This document governs ALL hybrid behavior in libtalos_geryon. It is
normative for the `geryon_h25519_512` and
`geryon_h448_1024` suites. Classical suites (`geryon_c25519`,
`geryon_c448`) follow the Signal X3DH, Double Ratchet, and XEdDSA
specifications directly and are out of scope here except where
cross-suite rules (downgrade rejection) apply.

Design lineage: the architecture follows the libtalos_signal hybrid
design (authoritative reference: implementation at
`~/Source/libtalos_signal_archive/`, NOT its stale specs), with the
deliberate changes listed in §1.2. It deliberately diverges from
Signal's PQXDH and ML-KEM Braid; see `docs/PQ_COMPARISON.md` for the
rationale.

---

## 1. Overview

### 1.1. Design summary

Every non-ephemeral asymmetric key is a paired classical+PQ structure:

- **Identity key (IK):** ECDH + ML-KEM + ML-DSA (long-term)
- **Signed prekey (SPK):** ECDH + ML-KEM, dual-signed by IK (medium-term)
- **One-time prekey (OPK):** ECDH + ML-KEM (single-use)
- **Ephemeral key (EK):** classical ECDH only (per-session, sender side)

The handshake performs one ML-KEM encapsulation per recipient key
alongside the classical X3DH DH operations, pairing each DH output with
the KEM secret from the same recipient key. The Double Ratchet mixes a
fresh ML-KEM shared secret into every DH ratchet step. Prekeys carry
both XEdDSA and ML-DSA signatures and verification requires both.
Initiator post-quantum authentication is achieved deniably via KEM
confirmation (§8) - never via transcript signatures.

Hybrid security model: session security holds if EITHER the ECDH
assumption OR the ML-KEM assumption survives. Within a hybrid suite no
KEM secret is ever optional, and hybrid signature verification always
requires both schemes.

### 1.2. Deliberate changes from the libtalos_signal implementation

| # | Change | libtalos_signal | geryon |
|---|--------|-----------------|--------|
| 1 | Combiner input order | classical-first: `H(dh ‖ kem_ss)` | **PQ-first**: `H(kem_ss ‖ dh)`, matching draft-ietf-sshm-mlkem-hybrid-kex |
| 2 | KDF info strings | fixed `"TalosSignal"` | **`geryon.<ver>.<suite>.<purpose>`** (§3.2) |
| 3 | Refresh-interval policy | global [1,100] ceiling only | **bundle-advertised [min,max] in signed flags** (§5.3) |
| 4 | Signed-prekey signed data | `pubkey ‖ timestamp` | **`pubkey ‖ timestamp ‖ flags`** (§5.2) |
| 5 | Initiator PQ auth | absent | **deniable KEM confirmation** (§8) |
| 6 | KDF_CK | NIST SP 800-108 counter mode, fixed ASCII contexts | **same construction; Label rebased to the suite-bound info string** (§7.4) |
| 7 | Wire format | unversioned structs | **version + suite bytes lead every top-level message** (§2.3) |
| 8 | AEAD | ChaCha20-Poly1305 (fixed) | **responder-advertised set {ChaCha20-Poly1305 (MTI), AES-256-GCM, AEGIS-256}, initiator-selected per session** (§7.5) |
| 9 | X448 tier KEM | ML-KEM-768 (stated intent) | **ML-KEM-1024** (no component below X448's 224-bit strength) |
| 10 | Crypto provider | libsodium + liboqs | **same providers, made policy: library-first - no in-house crypto where an acceptably-licensed library serves; in-house only as last resort (X448/Ed448 via libdecaf, D-XED-9; XEdDSA composition and XEd448 layers)** |
| 11 | Header encryption | none | **required in protocol v1, all suites** (§7.8) |

### 1.3. Roles and naming

- **Alice** - initiator: fetches Bob's prekey bundle, sends the initial
  message.
- **Bob** - responder: publishes IK/SPK/OPKs to the server, processes
  the initial message.
- **Server** - stores published keys, assembles bundles on demand,
  deletes each OPK as it hands it out.

---

## 2. Suites, Primitives, and Constants

### 2.1. Suite table

| | `geryon_h25519_512` | `geryon_h448_1024` |
|---|---|---|
| Suite ID byte | `0x02` | `0x04` |
| Suite name (ASCII, for KDF info) | `h25519_512` | `h448_1024` |
| Curve / curve_type byte | X25519 / `0x20` | X448 / `0x38` |
| Curve public/private key | 32 B | 56 B |
| Classical signature | XEdDSA, 64 B | XEd448, 114 B |
| KEM | ML-KEM-512 | ML-KEM-1024 |
| KEM ek / dk / ct / ss | 800 / 1632 / 768 / 32 B | 1568 / 3168 / 1568 / 32 B |
| PQ signature | ML-DSA-44 | ML-DSA-87 |
| ML-DSA pk / sk / sig | 1312 / 2560 / 2420 B | 2592 / 4896 / 4627 B |
| HASH | SHA-256 (32 B out) | SHA-512 (64 B out) |
| F prefix (X3DH §2.2) | 32 × `0xFF` | 57 × `0xFF` |
| AEAD | per-session selected (§7.5); same set for both suites | same |

Rationale: the 25519 tier targets 128-bit PQ strength
(category 1/2) to minimize overhead - messaging keys are short-lived;
the 448 tier is category 5 throughout so no component falls below
X448's 224-bit classical strength (CNSA 2.0-aligned). No à-la-carte
mixing: curve, signature, hash, and KEM strength move together.

All symmetric keys (SK, root, chain, message keys) are 32 bytes in both
suites. HASH and HKDF use the suite hash. HMAC is HMAC-HASH.

### 2.2. Suite pinning - no negotiation

The suite is a property of the identity key, fixed at identity
creation, and bound into every KDF (§3.2). A hybrid identity MUST NOT
complete a classical handshake and vice versa; there is no
hybrid-to-classical fallback path in code. An initial message whose
version or suite byte does not exactly match the responder identity's
suite MUST be rejected before any cryptographic processing.

### 2.3. Wire format conventions

- Every top-level wire object (prekey bundle, initial message, DR
  message) begins with `version` (1 byte, = `0x01`) and `suite_id`
  (1 byte, per §2.1).
- Multi-byte integers are big-endian.
- No padding bytes on the wire; in-memory alignment is an
  implementation concern.
- PKIDs, keys, signatures, and ciphertexts are raw byte strings.
- Reserved fields and flag bits MUST be zero on send and MUST be
  verified zero on receive (reject otherwise).

---

## 3. KDF Conventions and Suite Binding

### 3.1. Combiner (PQ-first, unconditional)

Wherever a classical ECDH output `dh` is fused with an ML-KEM shared
secret `kem_ss`:

```
hybrid_output = HASH(kem_ss ‖ dh)                       // §6.4, §7.3
hybrid_output = HASH(confirm_ss ‖ kem_ss ‖ dh)          // confirmation step only, §8.3
```

PQ input(s) first, classical last, matching
draft-ietf-sshm-mlkem-hybrid-kex §2.4. Do not reorder inputs. No KEM
secret is ever optional within a hybrid suite.

### 3.2. Info strings

Every HKDF invocation binds application, protocol version, suite, and
purpose:

```
INFO(purpose) = "geryon" ‖ "." ‖ "1" ‖ "." ‖ suite_name ‖ "." ‖ purpose
```

ASCII, dot-separated, no length prefixes (the grammar is fixed and
every field is drawn from a closed set). Defined purposes:

| Purpose | Used by |
|---------|---------|
| `x3dh` | handshake SK derivation (HKDF, §6.4) |
| `dr.root` | KDF_RK (HKDF, §7.3) |
| `dr.msg`, `dr.chain` | KDF_CK derivations (SP 800-108 Label, §7.4) |
| `dr.aead` | message-key to AEAD key/nonce expansion (SP 800-108 Label, §7.5) |
| `dr.sk` | SK to DR-seed expansion (HKDF; §7.8.1; D-DR-13) |
| `he.hka`, `he.nhkb` | SK to initial header-key expansion (HKDF; §7.8.1; D-DR-13) |
| `he.aead` | header-key to header AEAD key/nonce derivation (SP 800-108 Label; §7.8.3; D-DR-15) |
| `prekey` | ML-DSA context string for signed-prekey signatures (FIPS 204 ctx, §5.2; D-PQ-1) |

Example: `geryon.1.h25519_512.x3dh`. For HKDF the string is the
`info` parameter; for SP 800-108 KDF-CTR it is the `Label`.

Domain separation MUST NOT rely on input lengths or on ML-KEM's
internal binding of the encapsulation key into the shared secret; the
info string is the sole load-bearing separator.

### 3.3. PKID

```
PKID(key) = HASH(curve_type ‖ curve_pk ‖ mlkem_ek [‖ mldsa_pk])[0..3]
```

First 4 bytes of the suite hash over the encoded public key (identity
keys include the ML-DSA key). PKIDs are lookup handles, NOT security
values: they are grindable at 2^32 work. Implementations MUST fall back
to full-key comparison on PKID match and MUST NOT make any security
decision on a PKID alone. PKID comparison against zero (OPK-presence
detection) uses constant-time comparison.

---

## 4. Key Structures

### 4.1. Hybrid public key (SPK, OPK, ratchet keys)

| Offset | Field | h25519_512 | h448_1024 |
|--------|-------|-----------:|----------:|
| 0 | `pkid` | 4 | 4 |
| 4 | `curve_type` | 1 | 1 |
| 5 | `curve_pk` | 32 | 56 |
| 5+c | `mlkem_ek` | 800 | 1568 |
| | **Total** | **837** | **1629** |

The "encoded public key" (input to PKIDs and signatures) is the
structure from `curve_type` onward (833 / 1625 bytes).

### 4.2. Hybrid identity public key

Adds `mldsa_pk` after `mlkem_ek`, so the identity encoding is
`curve_type ‖ curve_pk ‖ mlkem_ek ‖ mldsa_pk`:

| | h25519_512 | h448_1024 |
|---|-----------:|----------:|
| Identity public key total | **2149** | **4221** |

**Safety number / fingerprint.** A hybrid identity is fingerprinted
over this complete encoding (all three public components), so the safety
number commits to the ML-KEM and ML-DSA keys as well as the curve key.
The custodian's own `gy_self_fingerprint`, the peer-side
`gy_bundle_fingerprint` over a fetched bundle or published registration,
and `gy_keychange.new_fp` all hash these same bytes and therefore match,
letting two sides compare out of band. The full encoding is also what a
verifier pins as `identity_pub` for a hybrid SAK cert (§5.5); the
server-side `gy_registration_identity_pub` returns exactly these bytes.

### 4.3. Keypairs (in-memory)

A hybrid keypair holds the public structure plus `curve_sk` (32/56),
`mlkem_dk` (1632/3168); identity keypairs add `mldsa_sk` (2560/4896).
Private keys are NEVER serialized for transmission; storage requires
authenticated encryption under a KDF-stretched key, and all key
material is zeroized on free (`secure_zero`).

Key generation: independent generation of each component
(XEdDSA-capable curve keypair for identities; plain ECDH keypair
otherwise; FIPS 203 `ML-KEM.KeyGen`; FIPS 204 `ML-DSA.KeyGen`), from
the OS CSPRNG. Constant-time discipline applies to generation paths.

---

## 5. Prekeys

### 5.1. Signed prekey structure

| Offset | Field | h25519_512 | h448_1024 |
|--------|-------|-----------:|----------:|
| 0 | `public_key` (§4.1) | 837 | 1629 |
| | `ik_id` (signer PKID) | 4 | 4 |
| | `timestamp` (u64 BE, Unix seconds) | 8 | 8 |
| | `flags` (u64 BE, §5.3) | 8 | 8 |
| | `ed_sig` (XEdDSA / XEd448) | 64 | 114 |
| | `mldsa_sig` (ML-DSA-44 / -87) | 2420 | 4627 |
| | **Total** | **3341** | **6390** |

### 5.2. Signed data (dual signatures over identical bytes)

```
signed_data = encoded_public_key ‖ timestamp_be64 ‖ flags_be64
ed_sig      = XEdDSA-Sign(IK.curve_sk, signed_data, Z64)
mldsa_sig   = ML-DSA.Sign(IK.mldsa_sk, signed_data, ctx = INFO("prekey"))
```

The ML-DSA context string (FIPS 204 `ctx`) is the §3.2 info string
with purpose `prekey`; verification supplies the same ctx. This makes
the ML-DSA identity key's single use (prekey signing, this suite,
this protocol version) cryptographically enforced rather than
conventional; the message bytes remain identical across both schemes
(the ctx is FIPS 204 scheme-level framing, not part of signed_data).
ML-DSA signing is hedged (FIPS 204 default, fresh randomness per
signature); the deterministic variant is not used
(docs/decisions/pq.md D-PQ-1).

Both signatures MUST cover exactly these bytes. Verification requires
BOTH signatures to pass; failure aborts the handshake with a diagnostic
code (`0x1` classical failed, `0x2` PQ failed, `0x3` both) that
implementations SHOULD log for compromise monitoring - a systematic
pattern of exactly one scheme failing across users indicates that
scheme is being forged. Never accept a single-signature bundle.

### 5.3. Flags field

```
bits  0..15  min_interval  (u16)   - lowest acceptable ML-KEM refresh interval
bits 16..31  max_interval  (u16)   - highest acceptable ML-KEM refresh interval
bit  32      AEAD: ChaCha20-Poly1305 supported - MUST be set (MTI baseline)
bit  33      AEAD: AES-256-GCM supported
bit  34      AEAD: AEGIS-256 supported
bits 35..63  reserved, MUST be zero
```

Constraints: `1 ≤ min_interval ≤ max_interval ≤ 100`. RECOMMENDED
advertisement is `[1, 20]` (bandwidth savings plateau at 20 - 48.6% vs
50.6% at 100 - while the vulnerable window grows linearly); owners on
CPU/battery-constrained devices MAY advertise up to 100 to reduce
ML-KEM keygen frequency. Because the flags sit inside the signed data,
a malicious server cannot widen the range (§10.4).

### 5.4. Prekey bundle

```
version (1) ‖ suite_id (1) ‖ IK (§4.2) ‖ SPK (§5.1) ‖ OPK (§4.1)
```

| | h25519_512 | h448_1024 |
|---|-----------:|----------:|
| Bundle total | **6329** | **12242** |

OPK is all-zeros (PKID zero) when the server has none left. Bundle
validation (initiator side, before any DH/KEM operation):

1. version/suite match the initiator's own suite, else abort.
2. IK PKID non-zero and recomputes correctly.
3. SPK PKID non-zero and recomputes correctly.
4. Dual signatures verify over `signed_data` (§5.2) with `flags`
   reserved bits zero and `min ≤ max` in range.
5. If OPK PKID non-zero: OPK PKID recomputes correctly.

Server behavior: Bob publishes IK, SPK (+signatures), and a batch of
OPKs (≤100 per batch). The server includes one OPK per bundle and
deletes it immediately; it MUST rate-limit bundle fetches to slow
OPK-draining attacks.

Two publish models are supported, exactly as in classical suites. The
directory-less path emits a complete one-shot bundle. The granular
directory path publishes the registration (IK + signed SPK, itself
bundle-shaped: the §5.4 layout with an all-zero OPK slot) and OPK
batches separately, and the untrusted server assembles a per-fetch
bundle. The server-side assembly free functions are suite-agnostic - a
directory dispatches on the self-describing suite byte and never
deserializes the material - so hybrid uses the same functions as
classical: `gy_opk_batch_count` / `gy_opk_batch_get` enumerate a batch
(each entry is one §4.1 hybrid public key), and `gy_bundle_assemble`
splices one popped OPK into the registration, yielding a bundle
byte-identical to a full §5.4 registration with its OPK slot filled.
The fetcher's `gy_initiate` re-validates it (§5.4). A hybrid OPK batch
entry is the §4.1 hybrid public key (`pkid ‖ curve_type ‖ curve_pk ‖
mlkem_ek`), wider than the classical entry by `mlkem_ek`; the batch
header is otherwise identical.

### 5.5. Application signing key (hybrid SAK)

The custody layer's application signing key (CUSTODY_SPEC §10) is an
identity-certified delegate the application uses to authenticate its own
requests. Certifying a SAK is the same category of act as signing a
prekey, so in a hybrid suite it follows the §5.2 rule: dual-scheme, with
no identity-signed artifact left at classical-only PQ strength. This is
custody, beside the protocol; it never signs message content or
transcripts and does not affect messaging deniability (which stays
offline in all suites).

The SAK keypair is a signer only (no ML-KEM component): an XEdDSA curve
keypair AND an ML-DSA keypair. The hybrid identity certifies it under
both schemes, and every per-request signature is a pair; verification
requires each signature of each pair to pass (never single-scheme, never
a downgrade).

```
cert_signed_data = INFO("appkey-cert") ‖ curve_type ‖ SAK.curve_pk
                                       ‖ SAK.mldsa_pk
                                       ‖ issued_at_be64 ‖ expiry_be64
                                       ‖ identity_pkid_be32
cert.ed_sig      = XEdDSA-Sign(IK.curve_sk, cert_signed_data, Z64)
cert.mldsa_sig   = ML-DSA.Sign(IK.mldsa_sk, cert_signed_data,
                               ctx = INFO("appkey-cert"))

req_signed_data  = INFO("appkey") ‖ app_ctx_len_be32 ‖ app_ctx ‖ msg
req.ed_sig       = XEdDSA-Sign(SAK.curve_sk, req_signed_data, Z64)
req.mldsa_sig    = ML-DSA.Sign(SAK.mldsa_sk, req_signed_data,
                               ctx = INFO("appkey"))
```

As in §5.2, the ML-DSA context string is the §3.2 info string for the
purpose (`appkey-cert` or `appkey`); both schemes sign identical bytes,
the ctx being FIPS 204 scheme-level framing. The cert binds BOTH SAK
public keys (`curve_pk ‖ mldsa_pk`) so neither half can be swapped, and
`identity_pkid` is the hybrid identity's. A per-request signature is the
concatenation `ed_sig ‖ mldsa_sig`.

Cert wire format:

```
version (1) ‖ suite_id (1) ‖ EncodeEC(SAK.curve_pub) ‖ SAK.mldsa_pk
            ‖ issued_at_be64 ‖ expiry_be64 ‖ identity_pkid_be32
            ‖ identity_ed_sig ‖ identity_mldsa_sig
```

Verification (custodian-free, server-side): the verifier pins the
identity out of band or via TOFU as the full hybrid identity encoding
(`curve_type ‖ curve_pk ‖ mlkem_ek ‖ mldsa_pk`, §4.2, the same bytes the
safety number hashes), NEVER taken from the cert. It checks both
identity signatures over `cert_signed_data`, the expiry, then both SAK
signatures over `req_signed_data`. All checks collapse to one uniform
failure code (no partial-validity oracle). The SAK is rotatable and
revocable with a bounded retained history, exactly like the classical
SAK.

---

## 6. Hybrid X3DH Handshake

### 6.1. Operations

With Bob's bundle validated, Alice generates a classical ephemeral
keypair EK and computes:

```
DH1 = ECDH(IK_A.curve_sk,  SPK_B.curve_pk)
DH2 = ECDH(EK.sk,          IK_B.curve_pk)
DH3 = ECDH(EK.sk,          SPK_B.curve_pk)
DH4 = ECDH(EK.sk,          OPK_B.curve_pk)          [if OPK present]

(ct_ik,  kem_ik)  = ML-KEM.Encaps(IK_B.mlkem_ek)
(ct_spk, kem_spk) = ML-KEM.Encaps(SPK_B.mlkem_ek)
(ct_opk, kem_opk) = ML-KEM.Encaps(OPK_B.mlkem_ek)   [if OPK present]
```

Bob mirrors with ECDH on his private keys and `ML-KEM.Decaps` on the
three ciphertexts. Corrupted KEM ciphertexts MUST take the FIPS 203
implicit-rejection path with a constant-time compare - never an
explicit error distinguishable from success at this stage (the
handshake then fails later at AEAD verification, uniformly).

### 6.2. Why EK is classical-only

EK appears in DH2-DH4 whose peer keys (IK_B, SPK_B, OPK_B) all carry
KEM counterparts; every pairing already has a PQ leg. A hybrid EK would
add ~800/1568 B to every initial message for no additional pairing.

### 6.3. Per-key pairing

Each DH output is fused (§3.1, PQ-first) with the KEM secret from the
same recipient key:

```
HDH1 = HASH(kem_spk ‖ DH1)      // both SPK_B
HDH2 = HASH(kem_ik  ‖ DH2)      // both IK_B
HDH3 = HASH(kem_spk ‖ DH3)      // both SPK_B
HDH4 = HASH(kem_opk ‖ DH4)      // both OPK_B      [if OPK present]
```

`kem_spk` intentionally appears twice (DH1 and DH3 both involve
SPK_B). Every HDH input to the final KDF is individually hybrid:
breaking one key's classical OR PQ component leaves that key's
contribution secure.

### 6.4. Shared secret

```
SK = HKDF-HASH(salt = zeros(hash_len),
               IKM  = F ‖ HDH1 ‖ HDH2 ‖ HDH3 [‖ HDH4],
               info = INFO("x3dh"),
               L    = 32)
```

All DH outputs, KEM secrets, and HDH values are zeroized immediately
after SK derivation. Alice deletes EK's private key; Bob deletes the
consumed OPK private key after successful processing.

### 6.5. Initial message

| Offset | Field | h25519_512 | h448_1024 |
|--------|-------|-----------:|----------:|
| 0 | `version` = 0x01 | 1 | 1 |
| 1 | `suite_id` | 1 | 1 |
| 2 | `ik` - Alice's identity public key (§4.2) | 2149 | 4221 |
| | `ek` - pkid ‖ curve_type ‖ curve_pk | 37 | 61 |
| | `ct_ik` | 768 | 1568 |
| | `ct_spk` | 768 | 1568 |
| | `ct_opk` (zeros if no OPK) | 768 | 1568 |
| | `ik_id` (Bob's IK PKID: the identity Alice encrypted to) | 4 | 4 |
| | `spk_id` (Bob's SPK used) | 4 | 4 |
| | `opk_id` (zeros if no OPK) | 4 | 4 |
| | `hybrid_flag` (u32 BE, §6.6) | 4 | 4 |
| | **Total** | **4508** | **9004** |

Followed by `ciphertext_len` (u32 BE) and the AEAD-encrypted first
message (§6.7). Bob determines OPK usage from `opk_id != 0`
(constant-time compare) and MUST abort if an OPK is claimed that he no
longer holds. Bob MUST verify `ik_id` equals his own identity PKID
and abort on mismatch (fast rejection of messages addressed to a
replaced identity). PKIDs embedded in the fully-carried `ik`/`ek`
structures are never trusted: the receiver recomputes them and aborts
on mismatch (docs/decisions/: D-X3DH-15, D-GEN-2).

### 6.6. hybrid_flag - refresh interval selection

```
bits  0..15  chosen mlkem_refresh_interval (u16)
bits 16..23  chosen aead_id (u8, §7.5; API request of 0 selects 0x01)
bits 24..31  reserved, MUST be zero
```

Alice MUST choose an interval within the `[min_interval, max_interval]`
advertised in Bob's signed prekey flags (a request of 0 to the API
selects `clamp(20, min, max)`) and an AEAD from Bob's advertised
support mask (§5.3). Bob MUST verify: reserved bits zero,
`1 ≤ interval ≤ 100`, `min ≤ interval ≤ max` for the SPK the message
references, AND the aead_id is in his advertised set - abort
otherwise. Both values are additionally authenticated by the
first-message AD (§6.7), so in-transit tampering fails AEAD
verification. Both are fixed for the life of the session.

### 6.7. Associated data

Identity hashes bind the AEAD stream to the complete hybrid
identities:

```
IKhash(X) = HASH(curve_type ‖ curve_pk ‖ mlkem_ek ‖ mldsa_pk)   // of X's IK

AD_session = IKhash(Alice) ‖ IKhash(Bob)                 // 64 / 128 B
AD_first   = AD_session ‖ hybrid_flag_be32               // 68 / 132 B
```

`AD_first` MUST be used for the first message (the one carried with
the handshake); `AD_session` for all subsequent application-level AD.
The Double Ratchet additionally appends the full encoded message
header to the AD of every message (§7.6).

### 6.8. Replay

An initial message that used no OPK is replayable (X3DH §4.2); the
OPK path self-protects because Bob deletes the OPK private key on
use. Library-side defenses (no replay cache needed):

1. **Base-key dedupe (REQUIRED).** Every session record stores the
   initiator ephemeral key `EK_A` it was created from. An incoming
   initial message whose `(IK_A, EK_A)` matches any existing session
   record - active or archived - MUST NOT create a new session; it is
   routed to the existing session as possible re-delivery, where
   message-key deletion (§7.4) makes an already-consumed first message
   undecryptable. A legitimate new session always carries a fresh
   `EK_A`, so re-initiation after state loss, device adds, and session
   racing are unaffected. (Dedupe on `IK_A` alone would block those
   Sesame-required flows - do not do that.)
2. **SPK retention bound.** Rotated-out SPK private keys are deleted
   after a grace period; older initial messages then cannot be
   processed at all. Total replay exposure =
   min(SPK private-key retention, session-record retention).
3. **KEM confirmation (§8).** An attacker-replayed session cannot
   proceed past the responder's first reply.

OPK replenishment is application-side (the library only generates
batches on request); the guarantees above hold with zero OPKs stocked.

### 6.9. Session lifecycle interaction

Sessions follow Sesame (Layer 4): one active session per (peer,
device) with archived alternates; failed decryption under the active
session triggers a bounded trial against archived sessions; a session
producing a valid message becomes active (this converges racing);
deletion is policy-driven via the store callbacks and zeroizes all key
material. Division of labor: the library owns base-key dedupe, key
deletion/zeroization, archived-session trial, and the PQ-pending
state (§8.4); the application owns OPK replenishment cadence, SPK
rotation schedule and grace period, and session retention policy.

Re-initiation (the orphan escape: forcing a fresh initiating session
when a device's session state is lost or has diverged) reuses the §6
initiation flow directly, with no distinct hybrid path. Insert
semantics demote any existing active session, so a fresh initiation
with a new `EK_A` IS the escape, and base-key dedupe (§7.4) routes
legitimate retransmits to the established session; §11 requires this to
be accepted while sessions exist.

---

## 7. Hybrid Double Ratchet

### 7.1. Relationship to the classical Double Ratchet

Identical to the Signal Double Ratchet except:

1. Ratchet keys are hybrid (curve + ML-KEM) with the ML-KEM component
   refreshed every `mlkem_refresh_interval` ratchet steps.
2. Every DH ratchet step mixes a fresh ML-KEM shared secret into the
   root KDF via the PQ-first combiner.
3. Message headers carry the KEM ciphertext (always) and the sender's
   ML-KEM encapsulation key (when refreshed).
4. The responder's first sending chain carries the KEM confirmation
   (§8).

Symmetric-key ratchet, skipped-message handling, and header roles are
unchanged. Header encryption (DR spec §4) IS required in protocol
version 1 for all suites (protocol v1 decision): the
`version` and `suite_id` bytes remain outer plaintext; everything
from `flags` inward (§7.6) is encrypted under header keys. Its
mechanics - initial header-key expansion, KDF_RK_HE, HENCRYPT/HDECRYPT,
the wire frame, and the receive algorithm with trial-decryption bounds
- are specified normatively in §7.8.

### 7.2. Session state (normative content, not layout)

Per session: own hybrid ratchet keypair; remote curve ratchet key;
cached remote ML-KEM ek + validity flag; current outbound KEM
ciphertext (+ confirmation ciphertext during the confirmation chain);
root key, send/receive chain keys (32 B each); counters `n_send`,
`n_recv`, `pn`; `mlkem_refresh_interval` and ratchet counter; skipped
message keys (≤ MAX_SKIP); peer-PQ-authentication state (§8.4);
the creating handshake's initiator base key `EK_A` (§6.8 dedupe);
AD from §6.7.

**Initialization (Alice, sender):** root key ← SK; remote ratchet key ←
Bob's SPK (curve + ML-KEM components); generate own hybrid ratchet
keypair; perform the initial sending ratchet (§7.3) immediately.
**Initialization (Bob, receiver):** root key ← SK; own ratchet keypair
← SPK keypair; remote ML-KEM key invalid until Alice's first header
arrives; ML-KEM ratchet counter ← interval (forces a fresh ML-KEM
keypair on his first ratchet, matching the archive implementation).

### 7.3. DH ratchet step

On receiving a header with a new remote curve ratchet key, the
receiver executes (and a sender ratchet mirrors steps 4-7):

```
1. pn ← n_send; n_send ← 0; n_recv ← 0
2. store remote curve key; if header carries mlkem_ek (flag §7.6),
   verify and cache it
3. receiving chain:
     kem_ss ← ML-KEM.Decaps(own.mlkem_dk, header.kem_ct)
     dh     ← ECDH(own.curve_sk, header.curve_pk)
     hdh    ← HASH(kem_ss ‖ dh)            // or confirmation form, §8.3
     (RK, CK_recv) ← KDF_RK(RK, hdh)
4. mlkem_ratchet_counter += 1
   if counter ≥ interval: generate fresh ML-KEM keypair, counter ← 0,
   mark "include mlkem_ek in headers" for the new chain
   generate fresh curve ratchet keypair (every ratchet)
5. sending chain:
     (kem_ct', kem_ss') ← ML-KEM.Encaps(cached remote mlkem_ek)
     dh'                ← ECDH(own.curve_sk', remote.curve_pk)
     hdh'               ← HASH(kem_ss' ‖ dh')
     (RK, CK_send) ← KDF_RK(RK, hdh')
6. store kem_ct' for inclusion in every header of this sending chain
7. zeroize kem_ss, dh, hdh, kem_ss', dh', hdh'
```

```
KDF_RK(rk, hdh) = HKDF-HASH(salt = rk, IKM = hdh,
                            info = INFO("dr.root"), L = 96)
                  → (new_rk = out[0..31], ck = out[32..63],
                     nhk = out[64..95])
```

`nhk` is the next header key for the mandatory header-encryption
variant (decisions register D-DR-14); its wiring (rotation into HKs/HKr
and NHKs/NHKr on each ratchet step) is specified in §7.8.2.

The encapsulation is fresh at EVERY ratchet step regardless of whether
the ML-KEM keypair was refreshed; the interval controls keypair
regeneration (and header size), not encapsulation frequency. A
receiver holding no valid cached remote ML-KEM key MUST reject a
header that does not include one.

### 7.4. Symmetric-key ratchet

KDF_CK is NIST SP 800-108r1 KDF in Counter Mode, PRF = HMAC-HASH
(retained from the archive implementation: NIST-specified, official
test vectors exist, and the Label carries the suite binding into
symmetric derivations):

```
mk  = KDF-CTR(K_in = ck, Label = INFO("dr.msg"),   Context = empty, L = 32)
ck' = KDF-CTR(K_in = ck, Label = INFO("dr.chain"), Context = empty, L = 32)
```

The fixed-input byte layout is pinned for all KDF-CTR uses in this
spec (SP 800-108r1 permits field variations; KATs require one form):

```
PRF_input = [i]_32BE ‖ Label ‖ 0x00 ‖ Context ‖ [L]_32BE
```

with the counter i starting at 1 and L expressed in BITS. This
matches the archive implementation byte-for-byte (the archive had no
Context field; it sits between the 0x00 separator and L, and is
empty here).

Single-block output (counter fixed at 1). Message keys are deleted
immediately after use. Chain and root keys never outlive their
ratchet step. Note this diverges from the Signal DR spec's
recommended single-byte HMAC constants; the libsignal oracle
therefore compares via a test-only compat parameterization
(docs/decisions/xeddsa.md, D-XED-11).

### 7.5. AEAD

Three AEADs are supported, all via libsodium, all with 32-byte keys.
Session security is set by the key-exchange strength, not the AEAD key
length; 256-bit keys meet or exceed both tiers' targets.

| aead_id | Algorithm | Nonce | Availability |
|--------:|-----------|------:|--------------|
| `0x01` | ChaCha20-Poly1305 (IETF) | 12 B | always - mandatory-to-implement, default |
| `0x02` | AES-256-GCM | 12 B | only where libsodium reports hardware AES support (`crypto_aead_aes256gcm_is_available()`); no software fallback exists - the fallback is algorithm-level (`0x01`). Note ARMv8 crypto extensions are optional (e.g. Raspberry Pi lacks them) - this gate has real reach on embedded targets |
| `0x03` | AEGIS-256 | 32 B | always (libsodium ≥ 1.0.19 includes a constant-time software AES-round fallback; not hardware-gated). Fastest option where AES intrinsics exist |

Selection: the responder advertises its supported set in the signed
prekey flags (§5.3, bit 32 always set); the initiator picks one and
encodes it in `hybrid_flag` (§6.6); the responder verifies the choice
is in its set. The AEAD is fixed for the session - it is never
renegotiated mid-session, and a header or message using a different
algorithm than the session's is a protocol error.

Per message (SP 800-108 KDF-CTR again, mk as the input key, per the
archive's approach to the DR spec's implementer-defined nonce
handling):

```
out   = KDF-CTR(K_in = mk, Label = INFO("dr.aead"),
                Context = aead_id ‖ n_be32,
                L = 32 + nonce_len)
key   = out[0..31];  nonce = out[32 .. 32+nonce_len-1]

ciphertext ‖ tag = AEAD-Encrypt(key, nonce, plaintext, AD_msg)
```

The message key `mk` is unique per message, so the derived nonce is as
well; deriving (rather than counting) keeps nonce handling stateless.
Tag verification is constant-time (libsodium's `_decrypt` functions
provide this). The first message (carried with the handshake) uses the
same construction with `AD_first` (§6.7).

### 7.6. Message header

```
version (1) ‖ suite_id (1) ‖ flags (u32 BE) ‖ curve_pk ‖ kem_ct ‖
pn (u32 BE) ‖ n (u32 BE) [‖ mlkem_ek] [‖ confirm_ct]
```

Flags:

```
bits 0..7   curve_type (0x20 / 0x38)
bit  8      MLKEM_EK_PRESENT    - header carries sender's ML-KEM ek
bit  9      CONFIRM_CT_PRESENT  - header carries KEM confirmation ct (§8)
bits 10..31 reserved, MUST be zero
```

Sizes:

| | h25519_512 | h448_1024 |
|---|-----------:|----------:|
| Compact (no ek, no confirm) | 814 | 1638 |
| + `mlkem_ek` | 1614 | 3206 |
| + `confirm_ct` | +768 | +1568 |
| Classical DR header, for comparison | ~46 | ~70 |

The complete encoded header is appended to the AEAD associated data of
its own message: `AD_msg = AD_session ‖ encoded_header` (`AD_first`
instead for the first message). Any header tampering - including the
flag bits - therefore fails authentication.

### 7.7. Skipped messages and commit-after-verify

MAX_SKIP = 1000 (recommended; MUST be bounded). Enforcement order is
normative:

1. Parse header; validate version/suite/reserved bits.
2. Check `pn`/`n` jumps against MAX_SKIP BEFORE deriving any key.
3. Derive candidate keys into temporaries.
4. Verify the AEAD tag.
5. ONLY THEN mutate session state: advance chains, store skipped keys,
   cache the remote ML-KEM key, update counters, process confirmation.

A message that fails authentication MUST leave the session state
byte-identical to its state before the message arrived. Skipped-key
records are indexed by (curve ratchet key PKID, message number) and
zeroized on use or eviction. Under header encryption (§7.8, required in
protocol v1) this index becomes (header key, n); see §7.8.5.

### 7.8. Header encryption (all suites)

Header encryption is REQUIRED in protocol version 1 for every suite,
classical and hybrid (decisions register D-DR-6). This section is the
normative specification of its mechanics. It applies to the classical
suites (`geryon_c25519`, `geryon_c448`) exactly as to the hybrid
suites, with the suite's own name in every INFO string (§3.2) and, for
classical suites, aead_id pinned to `0x01` (D-DR-3 amendment). The
`version` and `suite_id` bytes stay outer plaintext; everything from
`flags` inward (§7.6) is encrypted under header keys. The upstream
reference is the Signal Double Ratchet spec §4 (the header-encryption
variant); this section transcribes decisions D-DR-13 through D-DR-17
and the D-DR-3 amendment.

#### 7.8.1. Initial header-key expansion (D-DR-13)

The X3DH shared secret SK (hash_len bytes) is NEVER used directly by
the ratchet. Immediately after deriving SK, kex/ expands it into
exactly three 32-byte outputs via three HKDF-Expand calls (PRK = SK,
suite hash, §3.2 info strings), then zeroizes SK:

```
SKdr        = HKDF-Expand(SK, INFO("dr.sk"),   32)
shared_hka  = HKDF-Expand(SK, INFO("he.hka"),  32)
shared_nhkb = HKDF-Expand(SK, INFO("he.nhkb"), 32)
```

SKdr is the Double Ratchet initialization input everywhere the DR spec
says "SK" (Bob's initial root key = SKdr). The two header secrets seed
the initial header keys per the DR spec §4.5 mapping:

| Party | HKs | HKr | NHKs | NHKr |
|-------|-----|-----|------|------|
| Alice (initiator) | shared_hka | unset | first sending KDF_RK_HE | shared_nhkb |
| Bob (responder) | unset | unset | shared_nhkb | shared_hka |

Bob's HKs/HKr stay unset until his ratchet steps assign them; Alice's
NHKs is filled by the `nhk` output of her first sending ratchet
(§7.8.2), and her HKr is unset until Bob's first reply ratchets her
receiving side. All three expansion outputs are 32 bytes in both tiers
(header keys are AEAD keys, 32 bytes in every geryon AEAD; SKdr at 32
gives the root key one length from init). The expansion is
unconditional across all suites; hybrid suites change only how SK is
derived upstream (§6), never this expansion.

#### 7.8.2. Root KDF with header keys - KDF_RK_HE (D-DR-14)

Protocol v1 has exactly ONE root KDF, the HE variant. It extends
§7.3's KDF_RK by appending a next-header-key output:

```
KDF_RK_HE(rk, hdh) = HKDF-HASH(salt = rk, IKM = hdh,
                               info = INFO("dr.root"), L = 96)
                     → (new_rk = out[0..31], ck = out[32..63],
                        nhk = out[64..95])
```

`hdh` is the (hybrid-fused, §3.1) DH output of the ratchet step (§7.3),
or its confirmation form (§8.3). The output-tuple order (RK, CK, NHK)
matches the DR spec §4.5; the `dr.root` purpose is reused, not forked,
because HE is mandatory in v1 and no L = 64 variant coexists on any
wire (this is the same construction §7.3 already presents at L = 96,
with the third output no longer dormant). Header keys rotate on each
ratchet step per the DR spec §4.6:

- sending step: HKs ← NHKs, then NHKs ← the `nhk` from the sending
  KDF_RK_HE.
- receiving step: HKr ← NHKr, then NHKr ← the `nhk` from the receiving
  KDF_RK_HE.

#### 7.8.3. HENCRYPT / HDECRYPT (D-DR-15)

Headers encrypt under the SESSION's aead_id, the same AEAD as message
encryption (classical pins `0x01`); one AEAD choice is honored
everywhere, with no separate header-AEAD knob. Per header:

```
hdr_salt    = 16 fresh random bytes (transmitted in the clear)
key ‖ nonce = KDF-CTR(K_in = hk, Label = INFO("he.aead"),
                      Context = aead_id ‖ hdr_salt,
                      L = 32 + nonce_len(aead_id))
enc_header  = AEAD-Encrypt(key, nonce, header_plaintext,
                           AD = version ‖ suite_id)
```

`hk` is the sending header key HKs when encrypting, or a candidate
header key when decrypting; `header_plaintext` is the §7.6 header from
`flags` inward. KDF-CTR is the §7.4 SP 800-108 construction with the
same pinned fixed-input layout. The AEAD associated data is the
message's outer `version ‖ suite_id` bytes, so cross-version and
cross-suite header confusion is a cryptographic failure, not merely a
parse rejection.

`hk` NEVER keys an AEAD directly; its only use is as the KDF-CTR key.
The derived `key` and `nonce` are zeroized immediately after the AEAD
call on every path, including failure. `hdr_salt` is public wire data
and needs no zeroization. HDECRYPT reverses the construction: derive
`key ‖ nonce` from (candidate `hk`, received `hdr_salt`), AEAD-Decrypt
with the same AD; a tag failure yields no plaintext and leaves no
derived material in memory.

Routing a transmitted random salt through the PRF (rather than using it
as a raw nonce) realizes the DR spec §4.2 "random non-repeating value
transmitted with the ciphertext" option. Each header gets a fresh AEAD
key, so a (key, nonce) collision needs a 128-bit salt collision
(birthday bound 2^64 per epoch). The stateful-counter nonce option is
rejected: out-of-order delivery would force a trial-decryption window
per header key.

#### 7.8.4. Wire frame (D-DR-16)

The v1 Double Ratchet message is:

```
version ‖ suite_id ‖ hdr_salt(16) ‖ enc_header_len_be16 ‖
enc_header ‖ payload
```

`enc_header` is the HENCRYPT output (header ciphertext ‖ tag);
`payload` is the message AEAD ciphertext ‖ tag (§7.5), running to the
end of the envelope; `enc_header_len` is a 16-bit big-endian length.

Classical `enc_header` length is fixed; hybrid lengths vary (`kem_ct`
always present, `mlkem_ek` present at a refresh boundary, §7.3), which
is why the field exists. It is be16 because the largest possible
`enc_header` (h448_1024 at an ek refresh: 44-byte core ‖ ML-KEM-1024
`kem_ct` 1568 ‖ `mlkem_ek` 1568 ‖ 16-byte tag, plus framing) is about
3.2 KiB, so the 65535 ceiling is structurally unreachable and be32
would be two dead bytes on every message. The headroom holds even
against a hypothetical much larger KEM outside the closed suite set:
HQC at NIST level 5 (7245-byte ek, 14485-byte ct) would still yield
only about a 21.8 KiB header, comfortably within be16. (D-X3DH-15's
`ciphertext_len_be32` is not a counterexample: that field frames the
entire embedded first-DR-message, whose payload is unbounded
application data.) Receivers MUST reject an `enc_header_len` outside
the suite's valid set BEFORE any key derivation. The field leaks
nothing beyond the already-observable envelope length (no padding,
D-GEN-1).

The payload associated data binds the whole header wire unit:

```
AD_payload = CONCAT(AD, hdr_salt ‖ enc_header_len ‖ enc_header)
```

where `AD` is `AD_first` for the first message and `AD_session`
(§6.7 in hybrid suites; the classical spec-form AD in classical
suites) otherwise. Because the full header wire unit plays the DR
spec's `enc_header` role in CONCAT, splicing a header from one message
onto another message's payload fails the payload tag.

The first Double Ratchet message carried inside the X3DH initial
message (D-X3DH-15) is a COMPLETE frame of this layout, its own
`version ‖ suite_id` bytes included, so a single parser and an
identical HENCRYPT AD serve every position. HE applies from message
one: Alice's HKs = shared_hka exists at init (§7.8.1), and Bob's first
header decrypts via his NHKr (= shared_hka), triggering his first DH
ratchet step exactly per the DR spec §4.6.

#### 7.8.5. Receive algorithm and skipped-key indexing (D-DR-17)

The receive order follows the DR spec §4.6 exactly:

1. **Skipped-key trials.** One HDECRYPT trial per DISTINCT stored
   header key `hk`, using the received `hdr_salt`. On a header whose
   `n` matches a stored (hk, n) entry, consume that entry's message
   key.
2. **HKr.** HDECRYPT under the current receiving header key.
3. **NHKr.** HDECRYPT under the next receiving header key; success
   triggers the DH ratchet step (§7.3), including the header-key
   rotation of §7.8.2.

Skipped-key storage is re-keyed from D-DR-4's (ratchet-key PKID, n)
index to (hk, n). Header keys live once per epoch in a small
fixed-capacity epoch table; skipped entries hold (epoch ref, n, mk). An
epoch's `hk` is zeroized when its last entry is consumed or evicted.
Because `hk` is a full 32-byte key, this dissolves D-DR-4's
PKID-collision handling: `header.n` and the payload tag remain the
arbiters, and two epochs never share an `hk`.

Everything else from D-DR-4 / D-DR-8 carries over unchanged:
commit-after-verify staging (no live state or epoch-table mutation
until the payload tag verifies), the MAX_SKIP check before any
derivation, the 1000-entry cap, oldest-first and 1000-message aging
eviction, and zeroization on use, eviction, and teardown. No new
constant is introduced; the existing cap and aging policy are the
bound. Per-receive trial cost is (distinct stored hks) + 2 header
decryptions. Skipped keys generated on a ratchet step are stored under
the OUTGOING epoch's header key (the pre-step HKr that encrypted those
headers), per the DR spec §4.6 SkipMessageKeysHE.

#### 7.8.6. Classical instantiation

For the classical suites every parameter is pinned:

- aead_id = `0x01` (ChaCha20-Poly1305), nonce_len 12 (D-DR-3
  amendment); there is no AEAD advertisement or selection.
- INFO strings carry the classical suite name: `geryon.1.c25519.*` /
  `geryon.1.c448.*` for `dr.sk`, `he.hka`, `he.nhkb`, `dr.root`, and
  `he.aead`.
- The header plaintext is `flags(4) ‖ curve_pk ‖ pn(4) ‖ n(4)` (no KEM
  material), so `enc_header` is a fixed length and `enc_header_len` is
  constant: `geryon_c25519` has a 44-byte header (32-byte curve_pk),
  hence a 60-byte `enc_header` (44 + 16-byte tag); `geryon_c448` has a
  68-byte header (56-byte curve_pk), hence an 84-byte `enc_header`.

---

## 8. Initiator PQ Authentication - Deniable KEM Confirmation

### 8.1. Problem

After §6, Bob is PQ-authenticated implicitly (only he can decapsulate
`ct_ik`/`ct_spk`/`ct_opk`) and his prekeys are PQ-signed. Alice's
authentication rests solely on DH1 - classical. Her ML-DSA key is
transmitted but signs nothing, and no KEM ever points at her. A
quantum-active adversary who breaks the curve can forge initial
messages as any initiator. KEM-based implicit authentication of the
first flight is impossible (the verifier must encapsulate to the
prover's key, and Bob acts only after receiving the message), and
transcript signatures are forbidden - they would destroy offline
deniability, which is a geryon design goal.

### 8.2. Mechanism

In his FIRST sending chain of the session, Bob encapsulates to Alice's
identity ML-KEM key:

```
(confirm_ct, confirm_ss) = ML-KEM.Encaps(IK_A.mlkem_ek)
```

Every header of that chain sets flag bit 9 and carries `confirm_ct`
(chain headers are identical anyway; this keeps the confirmation
loss-tolerant). Bob zeroizes `confirm_ss` after the ratchet step; the
ciphertext persists in state for the duration of that chain only.

### 8.3. Key mixing

Both parties compute Bob's-first-chain ratchet fusion as:

```
hdh = HASH(confirm_ss ‖ kem_ss ‖ dh)
```

(the §3.1 confirmation form; PQ inputs first, confirmation secret
outermost). Alice obtains `confirm_ss` via
`ML-KEM.Decaps(IK_A.mlkem_dk, confirm_ct)`. From this step onward
every key in the session depends on Alice's PQ identity key.

Flag bit 9 is valid ONLY on the responder's first sending chain of a
session; a receiver MUST reject it anywhere else.

### 8.4. Authentication state

Bob's session exposes the peer state machine:

```
CLASSICAL_ONLY   - initial message accepted; PQ-pending
CONFIRM_SENT     - first reply (with confirm_ct) sent
PQ_CONFIRMED     - a message from Alice on a chain descended from the
                   confirmation step verified successfully
```

The API MUST expose this state. Policy on what to do while PQ-pending
(deliver-and-flag vs. hold) belongs to the application; the protocol
default is deliver-and-flag, matching Signal's async model.

### 8.5. Properties

- **Deniability preserved.** Every symmetric secret in the transcript
  - including `confirm_ss` - is known to both parties (encapsulator by
  generation, decapsulator by decapsulation), so either party can
  simulate the entire conversation. The 1-out-of-2 forgeability that
  X3DH's deniability rests on is intact. No signature over any
  conversation content exists.
- **Mutual PQ implicit auth after one round trip**, persistent (root-
  chain mixed), with PQ unknown-key-share protection binding the
  session to both PQ identities.
- **Replay hardening.** A replayed initial message yields a session
  whose Bob-side confirmation the replayer cannot decapsulate; it dies
  at Bob's first reply.
- **Residual risk (documented, accepted).** A quantum-active adversary
  can forge ONE initial flight and its first-message payload; the
  session cannot proceed past Bob's reply. This window is the price of
  deniability with standardized primitives; PQXDH never closes it at
  all.
- **Cost.** One extra ML-KEM ciphertext (768 / 1568 B) per message in
  one chain of the session.

### 8.6. Future (informative, non-normative)

Protocol version 2 may add first-flight deniable PQ authentication via
libtalos_voleith hybrid ring signatures: a 2-member ring over
{IK_A, IK_B} (Schnorr + VOLEitH two-stage Fiat-Shamir; VOLEitH follows
the FAEST v2.0 spec, a NIST PQC Round 2 additional-signatures
candidate, AES/SHAKE assumptions only), transcript bound into the
fs_seed. Blocked on: permissive relicense of libtalos_voleith
(currently AGPL), a ZK identity component (OWF leaf secret), and a
written security argument for the two-stage FS composition. The
version byte (§2.3) reserves the wire space.

---

## 9. Vulnerable Window Analysis (refresh interval)

Reusing an ML-KEM ratchet keypair for `interval` steps means that an
adversary who simultaneously (a) breaks the curve, (b) extracts that
ML-KEM private key, and (c) knows the current root key can follow the
root chain for at most `interval − 1` further ratchet steps before a
keypair refresh forces a new compromise. Fresh encapsulation per step
(§7.3) means (b) alone reveals nothing without (a) and (c); the root
key's role as HKDF salt means (a)+(b) alone reveal nothing without (c).

| interval | max exposed ratchet steps | bandwidth saving vs interval=1 |
|---------:|--------------------------:|-------------------------------:|
| 1 | 0 | 0% |
| 10 | 9 | ~46% |
| 20 | 19 | ~48.6% |
| 100 | 99 | ~50.6% |

Owners express their tolerance via the signed [min,max] advertisement
(§5.3); initiators choose within it (§6.6); the chosen value is
AD-authenticated (§6.7) and range-checked by the responder.

---

## 10. Security Considerations

### 10.1. Hybrid model

Confidentiality: secure if EITHER ECDH OR ML-KEM survives, at every
layer (handshake pairing §6.3, ratchet fusion §7.3). Prekey
authenticity: secure if EITHER XEdDSA OR ML-DSA survives (an attacker
must forge BOTH). Responder session authentication: classical implicit
(DH1/DH2) AND PQ implicit (KEM to IK_B). Initiator session
authentication: classical implicit from flight 1; PQ implicit from the
confirmation round trip (§8). ML-KEM and ML-DSA share the module-
lattice assumption; the classical leg is the hedge against a lattice
break, and §8.6 is the path to assumption diversity in authentication.

### 10.2. Forward secrecy and post-compromise security

Message keys deleted after use; chain/root keys never outlive their
step; zeroization is part of the protocol, not cleanup hygiene. PCS:
one honest round trip heals both the classical and PQ legs (subject to
§9 for the PQ ratchet-keypair window). One-time prekeys are deleted on
use; signed prekeys rotate on `timestamp` age per local policy.

### 10.3. Downgrade resistance

Suite pinned per identity (§2.2); version+suite bytes checked before
processing; suite bound into every KDF (§3.2); refresh interval bounds
signed (§5.3) and choice AD-bound (§6.6-6.7); reserved bits enforced
zero everywhere. There is no code path from a hybrid suite to a
classical handshake.

### 10.4. Trust in the server

The server can withhold OPKs (degrading initial forward secrecy to the
SPK's lifetime) and drop messages, but cannot: substitute prekeys
(dual signatures), widen interval bounds (signed flags), tamper with
the chosen interval (AD), or read anything.

### 10.5. Constant-time requirements

Unconditional: no secret-dependent branches or memory
indexing; constant-time ladders, ML-KEM implicit-rejection compare,
MAC verification, PKID-zero checks, and OPK-presence checks. ML-DSA
rejection-loop iteration count is the only permitted timing variation.

### 10.6. Randomness

Handshake security is contributory: weak initiator entropy weakens SK
regardless of responder key quality (ML-KEM hashes the recipient key
into the secret, limiting but not eliminating this). All randomness
from the OS CSPRNG (`rng.c`); XEdDSA requires 64 fresh random bytes
per signature.

### 10.7. Identity-key dual use

The curve identity key is used for both ECDH (DH1/DH2) and XEdDSA
signing, as in Signal. Formal analyses of X3DH/PQXDH model these
separately; this reuse is a known, accepted modeling gap (PQXDH §4
notes the same). The ML-KEM and ML-DSA identity components are
distinct keys with no cross-primitive reuse (the ML-KEM key is used
only for key agreement, the ML-DSA key only for signing). Within the
signing role, both the XEdDSA curve key and the ML-DSA key sign more
than one object type - prekeys (§5.2) and, if the application mints
one, the SAK certificate (§5.5) - but every such use carries a
distinct FIPS 204 context / domain-separation label (`prekey` vs
`appkey-cert`), so the signatures are not confusable across purposes.
The SAK's own per-request signatures are made by the separate SAK
keypair, never the identity key.

### 10.8. Initiator authentication and prekey compromise

Initiator authentication is implicit and rests on
`DH1 = DH(IK_A, SPK_B)` and its paired ML-KEM leg; the initiator signs
nothing (deniability). `DH1` is the only handshake value combining two
non-ephemeral keys - `DH2`/`DH3`/`DH4` each mix the initiator ephemeral
`EK`, and every KEM secret can be produced by the encapsulator. An
attacker who holds a responder's signed-prekey private key, or the
initiator's IK private key, or who can compute classical discrete logs
(a quantum adversary), can therefore forge an initiator's FIRST flight
(the initial message and its first-message payload) to that responder.
That single forged flight is accepted at the protocol layer.

In hybrid suites the forgery is CONTAINED, not prevented: it cannot be
extended into a sustained session. The responder's confirmation reply
(§8.3) encapsulates `confirm_ss` to the initiator's identity ML-KEM
key, which the forger cannot decapsulate, so every chain descended from
the confirmation step is unreachable to it unless the initiator's IK
ML-KEM key is also compromised. Until that confirmation verifies the
responder reports the peer as PQ-pending (`CLASSICAL_ONLY`, §8.4),
exposed through the API so an application MAY withhold trust from
pre-confirmation content. Net exposure is a single flight, bounded
further by SPK rotation (§10.2). Classical suites have no confirmation
step, so there SPK compromise permits sustained initiator impersonation
for the SPK lifetime, exactly as in X3DH.

Using an OPK does NOT mitigate this: the OPK leg `DH4 = DH(EK_A, OPK_B)`
mixes only the initiator's ephemeral key, and `kem_opk` is encapsulated
by the sender, so an OPK adds no secret the forger lacks. OPKs protect
initial-message forward secrecy and replay (§6.8), not initiator
authentication.

This property is confirmed by the formal model
(`formal/models/x3dh_secrecy.pv`): parameter agreement holds
for an honest initiator unless `CompromiseCurve(IK_A)`,
`CompromiseCurve(SPK_B)`, or `BrokenDH` fires. The pre-confirmation
impersonation is reproduced as an expected attack and the
post-confirmation agreement is proved (non-injectively) in
`formal/models/agreement.pv`; together they characterize the
PQ-pending boundary exactly as `gy_pq_pending()` reports it. See §10.9.

### 10.9. Formal results (symbolic model)

The hybrid protocol is machine-checked in ProVerif 2.04 under the
published PQXDH-analysis methodology (BJKS, USENIX Security 2024). The
models, per-query verdicts, and defeating-set commentary are in
`formal/` (the authoritative table is `formal/README.md`); the modeling
decisions are registered in `docs/decisions/formal.md` (D-FM-1..7). This
subsection states what the symbolic layer establishes and, as
importantly, what it does NOT.

**Theories.** The KEM is modeled PKE-style and NON-BINDING (D-FM-1):
`penc` is a public constructor and the shared secret is a fresh name not
bound to the encapsulation key, so no proof credits ML-KEM's internal ek
binding (the deployed FIPS 203 primitive is strictly stronger in that
one direction). The quantum attacker is `BrokenDH` (D-FM-2): all ECDH
secrets revealed. Compromise of each key class and a global `BrokenKEM`
break are event-gated, so every query names the exact set that defeats
it (BJKS "secret unless" style).

**Proved.**

- SK secrecy, classical and quantum attacker: SK stays secret unless the
  matching curve AND KEM secrets are compromised - the hybrid claim,
  §10.1 (secure if EITHER leg survives). `x3dh_secrecy.pv`.
- Parameter agreement on (suite, interval, aead_id), bound via `AD_first`
  (§6.6-6.7); the defeating set surfaced the §10.8 SPK-compromise
  finding. `x3dh_secrecy.pv`.
- Confirmation-chain authentication (§8): post-confirmation agreement and
  Alice-authenticates-Bob hold and are NOT defeated by `BrokenDH` (the
  hybrid PQ win); pre-confirmation initiator impersonation under
  `BrokenDH` is reproduced as the expected attack. Together they pin the
  PQ-pending state (§8.4). `agreement.pv`.
- ML-KEM public-key (ek) agreement (D-FM-4.5): same session implies the
  same ek, via the dual-signed `(curve_pk, mlkem_ek)` pairing (§5.2) with
  NO KEM binding credited - geryon's per-KEM-paired-DH design proves
  stronger here than PQXDH's lone unsigned KEM prekey (BJKS F4). The
  named P2 fallback was NOT needed. `ek_agreement.pv`.
- Forward secrecy, the §9 refresh-interval vulnerable window (as an
  expected attack) and its post-regeneration post-compromise-security
  restoration, and header-encryption derivation (header keys secret;
  revealing all header keys never reaches the root or message chain,
  D-FM-6). `ratchet.pv`.
- Attacker-model and encoding fidelity (D-FM-5): a classical suite falls
  to `BrokenDH`; a hybrid suite falls to `BrokenDH`+`BrokenKEM`; and with
  the paired DH removed the BJKS F4 re-encapsulation attack reappears -
  confirming the paired DH is the F4 defense and the KEM theory is
  genuinely non-binding. Three `falsify_*.pv` models.

**Not modeled (explicitly out of scope).**

- **Deniability** is argued in prose (§8.5): every transcript secret,
  including `confirm_ss`, is known to both parties, so either can
  simulate the conversation; no signature covers conversation content.
  ProVerif's equivalence machinery is not used for it here.
- **Injective (replay-free) agreement** is NOT mechanized. Injectivity
  rests on the §6.8 base-key dedupe and §7.2 monotonic message counters -
  a stateful atomic test-and-set outside ProVerif's applied-pi fragment
  (a mechanized query would report a spurious replay the counter
  defeats). It is carried by the prose replay-hardening argument (§8.5)
  and registered as a documented boundary (D-FM-4, D-FM-3).
- **Computational proofs** (CryptoVerif) are a possible later phase.
- **Ciphertext (ct) agreement** is unprovable by design under the
  non-binding theory (re-encapsulation yields a different ct for the same
  ss) and is deliberately NOT a query. The corresponding review
  obligation (D-FM-4): nothing downstream may key off ciphertext bytes as
  an identifier - §6.8 base-key dedupe uses the base key, not the ct.

One modeling correction was made spec-first during this work: the
refresh interval `iv` is public wire/policy data (§5.3, §6.6), so the
models publish it; a restricted stand-in had otherwise masked the F4
attack and made the ek-agreement proof vacuous (D-FM-5 finding).

---

## 11. Test Vector Requirements

Hybrid suites have NO external oracle (libsignal vectors cover
classical suites and bare primitives only). Required:

1. **Primitive KATs:** RFC 7748 (X25519/X448), RFC 8032 / XEdDSA
   vectors, RFC 5869 HKDF, RFC 4231 HMAC, and FIPS 203/204
   wrapper-conformance KATs for ML-KEM-512/1024 and ML-DSA-44/87.
   These are WRAPPER checks, not primitive re-validation: liboqs (like
   libsodium) validates its own arithmetic upstream, so geryon runs
   only a small bounded KAT set through each wrapper - sized to catch
   the wrapper bugs a round-trip misses (wrong parameter set, seed
   plumbing, implicit-rejection passthrough) - exactly as it runs a
   handful of RFC 7748 vectors through the libsodium-backed X25519
   wrapper rather than an exhaustive suite. No external ACVP oracle is
   pinned (D-PQ-3).
2. **Spec-derived protocol KATs**, generated with a seeded
   deterministic RNG and checked into `tests/vectors/`: PKIDs, signed
   prekey signed_data and both signatures, full handshake (with and
   without OPK) through SK, first-message AD, three ratchet steps each
   direction including an ML-KEM refresh boundary and the confirmation
   chain, skipped-message recovery.
3. **Negative tests:** tampered signatures (each scheme separately -
   verify the diagnostic codes), tampered KEM ciphertexts (implicit
   rejection, no oracle), tampered headers and flags (AEAD failure, no
   state mutation), interval outside signed bounds, aead_id outside
   the responder's advertised set, reserved bits set,
   cross-suite and cross-version initial messages, confirm_ct outside
   the responder's first chain, replayed initial message (base-key
   dedupe: no new session created, replayed first message
   undecryptable; and an attacker-continued replay dying at the
   confirmation), re-initiation with a fresh EK_A accepted while
   sessions exist, MAX_SKIP overflow, zeroization checks on teardown.
4. **Interop property tests:** both parties derive identical SK and
   chains across OPK/no-OPK, every legal interval, and out-of-order
   delivery within MAX_SKIP.
5. **Hybrid SAK (§5.5):** generate/rotate/export/sign round-trips
   through gy_appkey_verify with the pinned full hybrid identity
   encoding; both the cert and a per-request signature verify only when
   BOTH schemes pass (tamper each of the four signatures separately and
   confirm GY_ERR_VERIFY); expiry enforced; cert survives seal/unseal
   across a custodian reopen.

---

## 12. References

1. Signal specifications: X3DH, Double Ratchet, XEdDSA, Sesame
2. Signal PQXDH (informative; geryon diverges)
3. NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
4. RFC 7748, RFC 8032, RFC 5869
5. NIST SP 800-108r1-upd1 (KDF-CTR, §7.4/§7.5)
6. draft-ietf-sshm-mlkem-hybrid-kex (combiner pattern, §2.3.3/2.4)
7. `docs/decisions/` - the implementer-decision register (D-* IDs
   cited throughout this spec)
8. `docs/PQ_COMPARISON.md` - design rationale vs. Signal's PQ approach
9. libtalos_signal archived implementation
   (`~/Source/libtalos_signal_archive/`) - design lineage; NOT
   normative for geryon
10. Brendel et al., PKC 2022; Hashimoto et al., J. Cryptol. 2022 -
    deniable PQ AKE (background for §8)

---

## Open items

- `[RESOLVED 2026-08-19]` M5 close-out additions, made while bringing
  the hybrid custody + directory surface to parity with classical during
  the hybrid worked example. All additive; none change
  the handshake, ratchet, or KDF behavior:
  - §5.5 (new): the hybrid application signing key (SAK) is dual-scheme
    (XEdDSA + ML-DSA keypair, dual-certified, dual per-request signature,
    both-or-abort), mirroring §5.2 prekey signing so no identity-signed
    artifact drops to classical-only PQ authentication. Cert wire format
    and the `appkey-cert` / `appkey` domain-separation labels are given
    there; the §11 test list gained item 5.
  - §5.4: the server-side granular directory path (publish registration +
    OPK batch, assemble per fetch) is documented for hybrid; the assembly
    free functions are suite-agnostic (dispatch on the suite byte), and a
    hybrid OPK-batch entry is the §4.1 hybrid public key.
  - §4.2: the hybrid identity fingerprint / safety number is over the full
    identity encoding (`curve_type ‖ curve_pk ‖ mlkem_ek ‖ mldsa_pk`);
    `gy_self_fingerprint`, `gy_bundle_fingerprint`, and the SAK verifier's
    pinned `identity_pub` all use these same bytes.
  - §6.9: re-initiation (the orphan escape) reuses the §6 initiation flow
    directly, no distinct hybrid path (already required by §7.4 and §11).
- `[RESOLVED 2026-08-05]` the header-encryption section is written
  and normative at §7.8 (initial header-key expansion, KDF_RK_HE,
  HENCRYPT/HDECRYPT, wire frame, receive algorithm and
  trial-decryption bounds), transcribing D-DR-13..17 and the D-DR-3
  amendment. HE is REQUIRED in protocol v1 for all suites.
- `[RESOLVED 2026-08-10]` the ProVerif models in `formal/` are written
  and CI-gated (D-FM-7; ProVerif 2.04, GPL tooling under the oracle
  carve-out, nothing links into the library). Delivered across
  the formal-verification milestone: (1) full symbolic hybrid X3DH incl. KEM
  confirmation
  and interval/AEAD binding (x3dh_secrecy.pv, agreement.pv,
  ek_agreement.pv); (2) the quantum attacker as revealed-ECDH (D-FM-2
  BrokenDH) with the non-binding KEM theory (D-FM-1); (3) SK secrecy
  under both attacker classes, parameter agreement, post-confirmation
  agreement (injective form resolved as a documented modeling boundary,
  §10.9), and ek agreement (D-FM-4.5 proved as-is, no fork); (4) the
  bounded 3-epoch ratchet with FS/PCS/HE via phases (ratchet.pv); plus
  three falsification models (D-FM-5). The results are summarized in
  §10.9; per-query verdicts are in `formal/README.md`. Out of scope
  (unchanged): deniability (paper argument, §8.5) and CryptoVerif
  computational proofs (possible later phase).
- `[RESOLVED 2026-07-04]` XEd448 constants verified against
  xeddsa.pdf §6 (docs/decisions/xeddsa.md D-XED-8): hash = SHA-512,
  b = 456, encoded points/integers 57 bytes, signatures 2b = 114 B,
  hash_i prefix = 57-byte little-endian 2^456 - 1 - i. The 448-tier
  size tables in this document are confirmed correct. The 448-tier
  provider is also decided: libdecaf (ed448-goldilocks, MIT),
  vendored and pinned per docs/decisions/xeddsa.md D-XED-9; the M6
  milestone retains only its validation gate.
