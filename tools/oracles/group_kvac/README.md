# group_kvac oracle (both tiers)

Independent verify-equation oracle for geryon's classical group KVAC/NIZK layer
(GROUP_SPEC sections 5.1-5.3, D-GEN-6).

## Why this is not a zkgroup cross-check

geryon's group proofs are clean-room and **deliberately not zkgroup-byte-
compatible** (D-GRP-4): its own Fiat-Shamir transcript, domain separators, and
EncodeToG layout. A zkgroup/poksho byte-compat or interop cross-check is
therefore impossible by construction, and D-GEN-6 forbids a compat
parameterization. Instead `verify.py` is an **independent reimplementation**,
from the [CPZ] paper and GROUP_SPEC only, of

1. the sound conjunction Fiat-Shamir transcript, and
2. the per-equation verify relation `V[j] == sum_{i active} G[j][i]^r_i + c*P[j]`.

It reconstructs each proof's equation layout itself, so a wrong-generator-in-slot
or a wrong target in geryon's assembly fails here even though it would verify
against geryon's own matrix. No copyleft source is linked, read, or ported: the
oracle is clean-room from the paper - an independent-implementation cross-check,
not a copyleft generator like the libsignal oracles.

The independence is at the **protocol layer**. The group arithmetic underneath
is a shared primitive (as in geryon), validated separately (RFC 9496 for
ristretto255, RFC 7748/8032 and the libdecaf gate for decaf448):

- **255 tier**: libsodium ristretto255 (ctypes). Challenge **SHA-512 -> reduce**.
- **448 tier**: geryon's vendored libdecaf via the `decaf448_shim` shared lib.
  Challenge **SHAKE256 (114-byte squeeze) -> `decode_long`**.

The two tiers' transcripts differ in hash function, output length, reduction,
and point width. Because geryon's prover and verifier share that transcript
code, a bug in the 448 transcript would verify fine against itself and is
invisible to the 255 oracle; validating the 448 transcript independently is the
point of covering both tiers.

## Files

- `verify.py` - the independent verifier (protocol logic + both backends).
- `decaf448_shim.c` - byte-array wrappers over `decaf_448_*`, built as a shared
  lib (`decaf448_shim`) so Python can call decaf without sizing decaf structs.
- `run_ctest.sh` - ctest wrapper (regenerate + verify, skip-guarded).

## Running

The vector file is produced by geryon (`tests/group/test_group_kvac_emit.c`),
so regeneration needs a geryon build; 255 verification needs only Python 3 +
libsodium, 448 verification also needs the built `decaf448_shim` shared lib.

```
# 1. Build the emitter and the 448 shim:
cmake --build build --target test_group_kvac_emit decaf448_shim

# 2. Capture both tiers:
./build/tests/test_group_kvac_emit --dump > tests/vectors/group_kvac.vec

# 3. Verify independently (drop --decaf448 to check 255 only):
python3 tools/oracles/group_kvac/verify.py \
    --decaf448 build/libdecaf448_shim.so \
    tests/vectors/group_kvac.vec
```

The shim builds to a pinned path, `<build>/libdecaf448_shim.so` (or
`.dylib` on macOS), so the command above is a literal path - no `find`. You can
also point the oracle at it with `export GROUP_KVAC_DECAF448=build/libdecaf448_shim.so`
instead of `--decaf448`.

Expected: `PASS` for all ten records (five proofs x two tiers) and
`0 failed`. Without `--decaf448`, the five 448 records report `SKIP` and the
255 records still verify. Exit code 0 on success, 1 on any equation mismatch,
2 when nothing could be verified (no usable backend).

The proofs are randomized, so re-running the emitter yields a different (still
valid) vector file.

## Optional ctest

`run_ctest.sh` wires the above into CTest as `test_group_kvac_oracle`: it
regenerates a fresh vector file to a temp path and verifies it (passing the
built shim automatically), exiting 77 (CTest "Skipped") when python3 is absent
or no backend is usable. Per-tier backend gaps are reported but do not fail:

```
cmake --build build            # builds decaf448_shim alongside the tests
ctest --test-dir build -R test_group_kvac_oracle --output-on-failure
```
