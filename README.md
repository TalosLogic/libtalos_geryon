# libtalos_geryon

Clean-room C17 implementation of the Signal protocol (X3DH, Double Ratchet,
Sesame, XEdDSA) with library-custodied keys, offering a classical suite and a
post-quantum-hybrid suite. In the hybrid suite session security holds if
EITHER the ECDH or the ML-KEM assumption survives, and offline deniability is
preserved exactly as in the classical suite (no transcript signatures). The
hybrid design is geryon's own (see [docs/HYBRID_SPEC.md](docs/HYBRID_SPEC.md)),
not Signal's PQXDH. Protocol code is clean-room from the Signal specifications;
primitives come from permissively-licensed libraries by preference. The public
API is the single installed header `include/geryon.h`.

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
| (reserved) | 0x04 | | | |

The classical suite (`geryon_c25519`) provides **no** post-quantum
confidentiality; it exists for size/bandwidth-constrained deployments (32-byte
X25519 keys vs. ~1 KB of ML-KEM material). The hybrid suite
(`geryon_h25519_512`) mixes an ML-KEM secret into every X3DH DH and every
Double Ratchet step, and dual-signs prekeys with XEdDSA and ML-DSA. A classical
identity and a hybrid identity never interoperate; mixed deployments require
distinct identities. Suite ID 0x04 (`geryon_h448_1024`) is reserved for a
future 448-tier suite and is rejected before any cryptographic processing.

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
additionally exercising the PQ-pending transition and the ratchet KEM refresh.
See [examples/README.md](examples/README.md).

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
0.16.0 (ML-KEM and ML-DSA for the hybrid suite, built via ExternalProject),
and monocypher 4.0.3 (compiled directly). All three are permissively licensed.

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
  the hybrid suite (geryon's own PQ-hybrid design).
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
