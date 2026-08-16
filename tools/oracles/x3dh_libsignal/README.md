# x3dh_libsignal oracle

Generates the X3DH DH-stage known-answer vectors in
`tests/vectors/x3dh_libsignal.vec`, used by `tests/kex/test_x3dh_vectors.c` to
cross-check geryon's X3DH Diffie-Hellman stage (`src/kex/x3dh.c` DH1..DH4,
the X3DH specification section 3) against libsignal's X25519.

**Licensing boundary:** libsignal is AGPL-3.0 and is used ONLY as
a separate vector-generating process. Its code is never linked into geryon,
read for implementation, or ported. This tool is NOT part of the CMake build,
and the C test suite consumes only the checked-in `.vec` file, so building and
testing geryon needs no Rust toolchain. See `docs/TEST_ORACLES.md`.

## Scope (D-GEN-6)

The spike asked whether libsignal's public API can emit, for a synthetic
handshake, the five handshake private keys, the agreed X3DH secret **SK**, and
the **info string** libsignal used.

Finding: **partial.** libsignal exposes the per-DH agreement
(`PrivateKey::calculate_agreement`) but NOT the assembled X3DH master secret or
its HKDF info string - `initialize_alice_session` / session establishment
return an opaque `SessionRecord`, and no public accessor yields the pre-KDF
secret or the label. Per D-GEN-6 (no compat parameterization; drop what the
oracle cannot emit) this oracle therefore validates the **prescriptive DH
stage only** - the DH1..DH4 pairings and X25519 - and the SK / F-prefix / zero
salt / HKDF / info composition stays covered by the F-guard KAT and self-
vectors in `tests/kex/test_x3dh.c`.

API surface examined (public, by name/signature, from docs.rs - not read for
implementation): `KeyPair::generate`, `KeyPair::{public_key, private_key}`,
`PrivateKey::serialize`, `PublicKey::serialize`,
`PrivateKey::calculate_agreement`. No public item returns the X3DH master
secret or the KDF info string.

## Prerequisites

- Rust via rustup. The toolchain is pinned in `rust-toolchain` (matching the
  libsignal release below), so rustup selects it automatically.
- Build dependencies for libsignal's crate tree (Debian/Ubuntu names):

  ```
  sudo apt-get install -y build-essential clang cmake pkg-config protobuf-compiler
  ```

- Network access (the first build clones the libsignal repo).

## Regenerate

From this directory:

```
cargo run --release > ../../../tests/vectors/x3dh_libsignal.vec
```

Then commit the regenerated vectors together with `Cargo.lock`, and update
`docs/TEST_ORACLES.md` (libsignal tag, command, and the new file's SHA-256):

```
sha256sum ../../../tests/vectors/x3dh_libsignal.vec
```

## Version pinning

- libsignal tag is pinned in `Cargo.toml`, matching the `xeddsa_libsignal`
  oracle so both share one upstream.
- `Cargo.lock` is committed so regeneration is reproducible.

## Output format

UTF-8 text, one `key=hexvalue` per line, records separated by a blank line.
Each record is one synthetic handshake:

- `ik_a_sk`, `ek_a_sk` - initiator identity / ephemeral private scalars.
- `ik_b_pk`, `spk_b_pk` - responder identity / signed-prekey public
  u-coordinates.
- `opk_b_pk` - responder one-time-prekey public u-coordinate (only when
  `opk=01`).
- `dh1`..`dh4` - the four X3DH agreements DH1=(IK_A,SPK_B), DH2=(EK_A,IK_B),
  DH3=(EK_A,SPK_B), DH4=(EK_A,OPK_B); `dh4` present only when `opk=01`.
- `opk` - `01` if a one-time prekey is used, else `00`.

16 records with an OPK and 8 without.
