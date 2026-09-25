# libtalos_geryon

Clean-room C17 implementation of the Signal protocol (X3DH, Double Ratchet,
Sesame, XEdDSA) with library-custodied keys, offering classical suites and
post-quantum-hybrid suites. In the hybrid suites session security holds if
EITHER the ECDH or the ML-KEM assumption survives, and offline deniability is
preserved exactly as in the classical suites (no transcript signatures). The
hybrid design is geryon's own (see [docs/HYBRID_SPEC.md](docs/HYBRID_SPEC.md)),
not Signal's PQXDH. Protocol code is clean-room from the Signal specifications;
primitives come from permissively-licensed libraries by preference. The core
public API is the installed header `include/geryon.h`; two opt-in private-group
verticals add their own headers: a classical group system (v1.4.0)
adds `include/geryon_group.h` (client) and `include/geryon_group_server.h`
(server), and a quantum-safe group system (v1.5.0) adds
`include/geryon_qspgs.h` (client) and `include/geryon_qsgroups_server.h`
(server).

## Cipher suites

One suite is pinned per identity and never negotiated at runtime; it is bound
into every KDF, so a message under one suite cannot complete a handshake under
another (there is no fallback path in code, so no downgrade). Curve, signature
scheme, hash, and KEM strength move together.

| Suite | ID | Key exchange | Signatures | Hash |
|-------|----|--------------|------------|------|
| `geryon_c25519` | 0x01 | X25519 | XEdDSA | SHA-256 |
| `geryon_h25519_512` | 0x02 | X25519 + ML-KEM-512 | XEdDSA + ML-DSA-44 | SHA-256 |
| `geryon_c448` | 0x03 | X448 | XEd448 | SHA-512 |
| `geryon_h448_1024` | 0x04 | X448 + ML-KEM-1024 | XEd448 + ML-DSA-87 | SHA-512 |

The classical suites provide **no** post-quantum confidentiality. The smallest
(`geryon_c25519`) exists for size/bandwidth-constrained deployments (32-byte
X25519 keys vs. ~1 KB of ML-KEM material); `geryon_c448` is the CNSA-aligned
classical high-security tier (X448 + XEd448, SHA-512) for a larger classical
security margin. The hybrid suites (`geryon_h25519_512` and, at the highest
tier, `geryon_h448_1024`) mix an ML-KEM secret into every X3DH DH and every
Double Ratchet step, and dual-sign prekeys with XEdDSA and ML-DSA; session
security holds if either the ECDH or the KEM assumption survives. Identities of
different suites never interoperate; the suite is pinned per identity, there is
no downgrade path, and a cross-suite object is rejected before any cryptographic
processing. All four suites ship as of v1.3.0.

## Using the library

`include/geryon.h` is the only installed header and the entire public API. The
application owns storage (it implements the `gy_store_callbacks`) and the
network; the library owns the protocol.

```c
#include <geryon.h>

/* 1. Create a custodian (store callbacks + credential + this device's ids).
 *    The library, not the application, custodies every private key: no
 *    public entry point ever hands back cleartext key bytes. */
gy_custodian *cust;
gy_custodian_create(&cust, GY_SUITE_C25519, &store, cred, cred_len,
                    my_uid, my_uid_len, my_did, my_did_len,
                    /*clock*/ NULL, NULL, /*expiry cfg*/ NULL);
/* Pass GY_SUITE_H25519_512 here instead to create a hybrid identity; the
 * suite is fixed for that identity's lifetime. Every call below is
 * suite-agnostic (the wire objects self-describe). */
gy_custodian_generate_identity(cust, spk_timestamp, /*one-time prekeys*/ 100);

/* Publish the bundle (size query, then serialize). */
size_t blen = 0;
gy_publish_bundle(cust, NULL, &blen);
uint8_t *bundle = malloc(blen);
gy_publish_bundle(cust, bundle, &blen);

/* 2. Send: open a transaction, encrypt per device, commit on server accept. */
gy_send_open(cust);
uint8_t msg[512]; size_t mlen = sizeof msg;
gy_encrypt(cust, peer_uid, peer_uid_len, peer_did, peer_did_len,
           pt, ptlen, msg, &mlen);       /* GY_ERR_STATE => no session:
                                          * fetch a bundle, gy_initiate() */
gy_commit(cust);                         /* or gy_rollback(cust) on reject */

/* 3. Receive: one self-committing call; GY_ERR_VERIFY is the uniform reject. */
uint8_t out[512]; size_t olen = sizeof out;
gy_receive(cust, from_uid, from_uid_len, from_did, from_did_len,
           wire, wire_len, out, &olen);

/* 4. Reopen later from the store and the same credential alone. */
gy_custodian_close(cust);
gy_custodian_open(&cust, &store, cred, cred_len);
```

Output buffers use the OpenSSL convention (`out == NULL` reports the size in
`*out_len`, then call again with a buffer that large). A `gy_custodian` also
holds an application signing key (SAK) for domain-separated request
signing (`gy_custodian_sign`), verified independently of any custodian by
`gy_appkey_verify` - see `include/geryon.h` and
[docs/CUSTODY_SPEC.md](docs/CUSTODY_SPEC.md).

### REQUIRED integration rules

- **Bounded send retry (Sesame 6.5).** A send the server rejects with a stale
  device list must be retried a *bounded* number of times: reconcile the delta
  with `gy_accept_identity` / `gy_purge_device` / a fresh `gy_initiate`, then
  re-prepare. The library exposes one iteration; the retry counter (suggested
  max 8) is yours.
- **Concurrency (D-GEN-8).** A `gy_custodian` is not thread-safe or
  re-entrant. Use one per thread, and never call back into the library from
  inside a store callback it invoked.
- **Storage (D-GEN-4).** You protect the opaque blobs at rest; the library
  never caches records and never retains plaintext (D-SES-8).
- **Identity key change** surfaces distinctly as `GY_ERR_KEY_CHANGED` (with
  fingerprints); accept it explicitly with `gy_accept_identity` before retrying.

## Example

`examples/` holds a multi-process end-to-end worked example: an untrusted relay
plus per-client sealed stores, driving publish/fetch, X3DH + Double Ratchet
messaging, the prekey lifecycle, SAK-authenticated requests, and restart
persistence over `include/geryon.h` only. It doubles as a deterministic
pass/fail smoke test (`ctest --test-dir build -R demo`). A parallel
`geryon_hybrid_demo` runs the same lifecycle under `geryon_h25519_512`,
additionally exercising the PQ-pending transition and the ratchet KEM refresh,
and `geryon_c448_demo` runs it under the classical 448 tier. See
[examples/README.md](examples/README.md).

## Private groups (opt-in)

v1.4.0 adds a private group system (the classical [CPZ] design) as an **opt-in**
vertical: a separate set of libraries and two additional public headers, so a
deployment that does not use groups links none of it.

- **Client** (`include/geryon_group.h`): the group client *extends* a custodian.
  A group's secret state (the GroupMasterKey, cached credentials, the user's own
  ProfileKey) seals into the custodian's existing store, and nothing derived is
  cached. Members prove anonymous membership with keyed-verification credentials
  (an algebraic MAC plus Schnorr NIZKs) and encrypt their UID and ProfileKey, so
  the group server learns neither.
- **Server** (`include/geryon_group_server.h`): a *separate, stateless* target
  that holds only the group service keys, issues and verifies credentials, and
  never touches the messaging custodian. The client/server split is enforced at
  link time (a client binary cannot carry issuance code).
- **Message delivery** is ordinary pairwise messaging: group messages fan out
  over the 1:1 sessions above, and the GroupMasterKey is handed to a new member
  inside a 1:1 session (a `GROUP_KEY_DISTRIBUTION` envelope). There is no
  separate group ratchet.
- **Group format version.** Each group is created at an immutable capability
  epoch bound into its GroupID, so an existing group never changes shape under
  the clients already in it; a client that lacks a newer version declines to
  join it rather than mishandle it.

The classical group type provides **no** post-quantum confidentiality or
anonymity (its guarantees rest on discrete-log assumptions), exactly like the
classical messaging suites. Link `geryon_group` (client) and/or
`geryon_groups_server` (server); both are `EXCLUDE_FROM_ALL`. See
[docs/GROUP_SPEC.md](docs/GROUP_SPEC.md) and the worked example in
[examples/README.md](examples/README.md).

## Quantum-safe private groups (opt-in)

v1.5.0 adds a quantum-safe private group system (QSPGS) as a second opt-in
vertical, side by side with the classical one, so a deployment can use either,
both, or neither. Group authentication is post-quantum throughout: members
present under per-version rerandomized ML-DSA keys (KR-ML-DSA), so the server
and other members cannot link a member across group versions or to its
long-term identity.

- **Client** (`include/geryon_qspgs.h`): the group client *extends* a custodian.
  All group secret state (the group key, per-epoch user keys, the member's
  rerandomizable signing key) seals into the custodian's existing store, and
  nothing derived is cached. The identity key certifies the member's base
  verification key and per-epoch user key, binding membership to the custodied
  identity without any transcript signature.
- **Server** (`include/geryon_qsgroups_server.h`): a *separate, stateless*
  target that holds only the service keys and verifies cores, appendix lines,
  and bearer tokens; it never touches the messaging custodian. The client/server
  split is enforced at link time.
- **Versioned state with an appendix log.** A group advances through
  admin-signed cores (the membership snapshot) and member-appended lines (joins,
  leaves, key refreshes, attribute changes) that an admin later folds into a new
  core. Each group is created at an immutable format epoch and field-AEAD choice
  bound into its signed header; field encryption is pinned per group
  (ChaCha20-Poly1305 default or AEGIS-256) with no downgrade path.

Link `geryon_qspgs` (client) and/or `geryon_qsgroups_server` (server); both are
`EXCLUDE_FROM_ALL`. See [docs/QSPGS_SPEC.md](docs/QSPGS_SPEC.md) and the worked
example in [examples/README.md](examples/README.md).

## Building

Requires CMake >= 3.22, a C17 compiler (gcc or clang), and the autotools
toolchain (libsodium is built from source). Fetch submodules first.

```sh
git submodule update --init
cmake -B build
cmake --build build
```

Dependencies are vendored as pinned submodules under `third_party/`:
libsodium 1.0.22 (classical primitives, built via ExternalProject), liboqs
0.16.0 (ML-KEM and ML-DSA for the hybrid suites, built via ExternalProject),
libdecaf/ed448-goldilocks v1.0.3 (X448 and the 448 field/scalar/point
primitives for the 448-tier suites `geryon_c448` and `geryon_h448_1024`, the
448 C-source slice compiled directly), and monocypher 4.0.3 (compiled
directly). All four are permissively licensed.

### Sanitizers

```sh
cmake -B build -DGERYON_SANITIZE=address,undefined
cmake --build build
```

## Testing

```sh
ctest --test-dir build -LE slow          # default: skip iterated/slow vectors
ctest --test-dir build                   # full suite including `slow`
ctest --test-dir build -R descriptor_discipline   # D-GEN-7 audit only
```

The library is layered: `geryon_core` (Layer 1 primitives), `geryon_kex`
(Layer 2, X3DH + prekeys), `geryon_ratchet` (Layer 3, Double Ratchet),
`geryon_session` (Layer 4, Sesame session management), and `geryon_proto`
(Layer 5, wire format + the `include/geryon.h` API); each links only the layer
below. The `scripts/layer_audit.sh` CI check enforces the include direction, a
`nm`-based proof that Layer 5 references no ratchet/core symbol, and that
`geryon.h` compiles standalone as C++. Layer-4 integration/property tests
(`tests/api/`, including a `slow` soak) drive `include/geryon.h` only. Layer 2/3
tests recompile their sources with
`-DGY_TEST_HOOKS` for operation counters and injectable seams, and share a
thin two-party harness under `tests/harness/`. The `descriptor_discipline`
audit (`tests/audit/`) enforces that `kex/` and `ratchet/` reach primitives
only through the suite descriptor (D-GEN-7).

Some oracle-backed tests read checked-in vectors under `tests/vectors/`
(generated by the AGPL oracles in `tools/oracles/`, never linked into geryon);
they skip cleanly when a vector file is absent, so no Rust toolchain is needed
to build or test. The dudect timing harness is opt-in:

```sh
cmake -B build-timing -DGERYON_BUILD_TIMING=ON
cmake --build build-timing
ctest --test-dir build-timing -L timing  # bounded self-check
build-timing/tests/timing/geryon_dudect --target kdf_ctr   # a full run
```

## Formatting

Style is OpenBSD KNF (style(9)) with 4-space indentation, enforced by the
tracked `.clang-format`. Check formatting without modifying files:

```sh
cmake --build build --target format-check
```

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) - whole-system design overview.
- [docs/HYBRID_SPEC.md](docs/HYBRID_SPEC.md) - the normative specification for
  the hybrid suites (geryon's own PQ-hybrid design).
- [docs/GROUP_SPEC.md](docs/GROUP_SPEC.md) - the classical private group system
  (the [CPZ] design; opt-in vertical).
- [docs/QSPGS_SPEC.md](docs/QSPGS_SPEC.md) - the quantum-safe private group
  system (QSPGS, the [CFG+] design; opt-in vertical).
- [docs/PQ_COMPARISON.md](docs/PQ_COMPARISON.md) - the hybrid design rationale
  against Signal's PQ approach.
- [CHANGELOG.md](CHANGELOG.md) - broad strokes per release.
- [docs/decisions/](docs/decisions/README.md) - implementer decision
  register (build/test toolchain baseline is **D-GEN-5**).
- [docs/CUSTODY_SPEC.md](docs/CUSTODY_SPEC.md) - the key-custody design.
- [formal/](formal/README.md) - ProVerif symbolic models of the hybrid
  protocol and the CI verdict table.
- [docs/TEST_ORACLES.md](docs/TEST_ORACLES.md) - provenance and license of
  the external test-vector oracles.

## License

Library code: AGPL-3.0-only. Every linked or vendored dependency is
permissively licensed so the combined work is redistributable under the AGPL;
copyleft dependencies are confined to test-vector oracle tooling only (see
[docs/TEST_ORACLES.md](docs/TEST_ORACLES.md)), never linked into the library.
