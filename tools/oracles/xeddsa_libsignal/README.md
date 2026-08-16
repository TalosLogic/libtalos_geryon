# xeddsa_libsignal oracle

Generates the XEdDSA known-answer vectors in
`tests/vectors/xeddsa_libsignal.vec`, used by
`tests/core/test_xeddsa_vectors.c` to validate `src/core/ed25519.c` against
libsignal's Curve25519 XEdDSA.

**Licensing boundary:** libsignal is AGPL-3.0 and is used ONLY as
a separate vector-generating process. Its code is never linked into geryon,
read for implementation, or ported. This tool is NOT part of the CMake build,
and the C test suite consumes only the checked-in `.vec` file, so building and
testing geryon needs no Rust toolchain. See `docs/TEST_ORACLES.md`.

## Prerequisites

- Rust via rustup. This directory pins the toolchain in `rust-toolchain.toml`
  (matching the libsignal release below), so rustup selects it automatically;
  no global default is required.
- Build dependencies for libsignal's crate tree (Debian/Ubuntu names):

  ```
  sudo apt-get install -y build-essential clang cmake pkg-config protobuf-compiler
  ```

- Network access (the first build clones the libsignal repo).

## Regenerate

From this directory:

```
cargo run --release > ../../../tests/vectors/xeddsa_libsignal.vec
```

Then commit the regenerated vectors together with `Cargo.lock`, and update
`docs/TEST_ORACLES.md` (libsignal tag, command, and the new file's SHA-256):

```
sha256sum ../../../tests/vectors/xeddsa_libsignal.vec
```

## Version pinning

- libsignal tag is pinned in `Cargo.toml` (`libsignal-protocol { git, tag }`).
- `rand` / `rand_chacha` must resolve to the same `rand_core` major version
  that libsignal uses, so `ChaCha20Rng` satisfies the `CryptoRng` bound on
  `KeyPair::generate` and `calculate_signature`. If a future libsignal bump
  changes that, align these versions and, if the API shifts, `src/main.rs`.
- `Cargo.lock` is committed so regeneration is reproducible.

## Output format

UTF-8 text, one `key=hexvalue` per line, records separated by a blank line.
Two record kinds:

- Sign record: `sk`, `pk`, `msg`, `z`, `sig`. `z` is the 64-byte XEdDSA nonce
  captured from the signing RNG so the signature is reproducible;
  `gy_xeddsa_sign_z(sk, msg, z)` must equal `sig`.
- Verify record: `pk`, `msg`, `sig`, `valid` (`01`/`00`).

256 sign records (message lengths varied 0..8192) and 64 verify records (half
valid, half with one flipped bit).

Sign-bit-0 keys only: libsignal diverges from the XEdDSA paper for keys whose
E = kB has sign bit 1, storing that sign in bit 255 of s.  geryon follows the
paper (canonical s), so the two agree byte-exact only for sign-bit-0 keys.  The
oracle regenerates keys until the signature's s bit 255 is clear.  See
`docs/decisions/xeddsa.md` D-XED-11 and `docs/TEST_ORACLES.md`.
