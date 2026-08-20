# Timing-leak validation harness

A [dudect](https://github.com/oreparaz/dudect)-style two-class Welch t-test
harness. It measures each target function under a fixed-secret class A against
a random-secret class B; a secret-dependent run time shows up as a large `|t|`.
Both classes perform identical non-cryptographic setup (see "Target framing"
below), so the secret VALUE is the only difference the primitive sees.
The X25519, XEdDSA, and AEAD targets exercise the libsodium-backed wrappers
directly. PQ primitives are NOT re-timed here: liboqs validates its own
ML-KEM/ML-DSA constant-timeness (docs/decisions/pq.md D-PQ-4), so the PQ
coverage is one target over geryon's OWN composition code, the hybrid X3DH
responder fusion, where the liboqs decapsulation is common-mode across both
classes.

This harness links the geryon library, so it is a first-party ISC tool rather
than external test-oracle tooling; the copyleft carve-out does not apply here.

## Method

For each target, the harness alternates classes trial by trial. A trial runs
the target `reps_per_trial` times inside one timer window (RDTSCP+LFENCE on
x86_64, CNTVCT_EL0 behind an ISB on aarch64, `clock_gettime` otherwise). After
collecting the samples it drops the extreme percentiles (default `[1%, 99%]`,
which removes scheduler and interrupt outliers) and computes Welch's
two-sample t-statistic on the cropped, sorted arrays.

Verdict (per `dudect` convention):

- `|t| > 10` at any point: **FAIL** (a leak).
- `|t| <= 10` with at least 5e5 samples per class (>= 1e6 total): **PASS**.
- Otherwise: **INCONCLUSIVE** (run longer).

The `sentinel_leak` target is a deliberately data-dependent early-exit loop
that MUST be flagged; `sentinel_clean` is a fixed-iteration fold that must NOT
be. They validate the harness itself. Because `sentinel_leak` is designed to
fail, `--all` returns a nonzero status by construction; use it for a survey and
read each target's individual verdict, or run a single real target with
`--target NAME` for a clean pass/fail.

## Building and running

The harness is off by default. Enable it explicitly:

```
cmake -B build -DGERYON_BUILD_TIMING=ON
cmake --build build --target geryon_dudect
```

Run every target (survey; nonzero exit expected from the leak sentinel):

```
./build/tests/timing/geryon_dudect --all --verbose
```

Validate one primitive to a clean verdict:

```
./build/tests/timing/geryon_dudect --target const_memcmp
./build/tests/timing/geryon_dudect --target x25519
./build/tests/timing/geryon_dudect --target xeddsa_sign
./build/tests/timing/geryon_dudect --target aead_tag_reject
./build/tests/timing/geryon_dudect --target kdf_ctr
./build/tests/timing/geryon_dudect --target he_tag_reject
./build/tests/timing/geryon_dudect --target he_recv_trials
./build/tests/timing/geryon_dudect --target hybrid_x3dh_resp
```

## Target framing (D-GEN-10)

How the two classes are set up decides whether `|t|` measures a real leak or a
measurement artifact. The register entry is authoritative; the rules:

1. **Tag/MAC-rejection targets are forgery-vs-forgery, never valid-vs-corrupt.**
   `aead_tag_reject`, `dr_tag_reject`, `he_tag_reject`, and `he_recv_trials`
   compare two forgeries with the tag byte flipped at different positions. A
   valid-vs-corrupt split would just time the accept path doing more work
   (running the stream cipher to produce plaintext) than the reject path -- an
   accept-vs-reject difference on a public distinction, not a secret leak.
   Forgery-vs-forgery isolates the real question: does the reject time depend on
   WHERE the tag mismatches (a padding-oracle-style early-exit compare)?
   `he_tag_reject` wraps HDECRYPT (`gy_he_decrypt`); `he_recv_trials` wraps the
   full HE receive path (D-DR-17) with a fixed number of stored epoch header keys,
   so the skipped-trial loop runs a constant HDECRYPT count on both classes
   (the constant count itself is asserted by the op counters, not by
   timing; see D-DR-19).
2. **Fixed class-A secret is a single random-looking draw, not a repeated
   constant byte.** An all-`0xNN` key gives class A zero input variance and a
   degenerate Hamming weight, which alone can inflate `|t|` on a DVFS-sensitive
   core. Applies to `kdf_ctr`, `xeddsa_sign`, `x25519`.
3. **Both classes do identical non-cryptographic setup work.** Both draw from
   the RNG every trial (class A then overwrites the draw with its fixed secret),
   so only the secret VALUE differs into the primitive. Otherwise only class B
   pays the RNG cost, which perturbs the cache/predictor/frequency state the
   next timer window inherits, and `|t|` partly reflects "did we just call the
   RNG." Applies to `kdf_ctr`, `xeddsa_sign`, `x25519`.

4. **`hybrid_x3dh_resp` is valid-vs-corrupt, and here that is correct.** This
   is the one PQ target (D-PQ-4): it measures geryon's PQ-first fusion
   `HDH = HASH(kem_ss || dh)` and the SK/seed-triple KDF inside
   `gy_hybrid_x3dh_respond`, not the liboqs decapsulation (common-mode: both
   classes decapsulate one ciphertext). Class A responds to a valid
   initial-message prefix; class B flips one byte of the unauthenticated
   `ct_spk` field in that prefix. Unlike the tag-rejection targets, valid-vs-
   corrupt does NOT become an accept-vs-reject split here: FIPS 203 implicit
   rejection turns a corrupt ciphertext into a pseudorandom shared secret with
   no error and no branch, so both classes take the identical `GY_OK` path and
   any `|t|` is a genuine secret-dependent leak in geryon's fusion/KDF. The
   responder is stateless (secrets written to caller scratch), so the shared
   fixture is never mutated. `ct_spk` is the attacker-reachable KEM-oracle
   surface; the ratchet's KEM ciphertext is AEAD-authenticated and so was
   deliberately left uncovered (D-PQ-4 amendment).

**Not-gaming litmus.** A framing change is legitimate only if it does not weaken
the test's power to detect a real key-dependent leak. Rule 3 adds work to the
previously-faster class and leaves class B varying its secret every trial, so it
cannot manufacture a pass. NOT allowed, because each blinds the test: widening
the crop to discard the samples that show an effect, cutting the sample count,
or making class B use a fixed secret too (a fixed-vs-fixed split cannot detect
key dependence at all).

**Reading a result.** Judge by the shape of the running `|t|` (`--verbose`), not
the final number. Under the null `|t|` is a bounded, mean-reverting walk; a real
effect grows ~sqrt(N) (a monotone climb). A steady climb below the `|t| < 10`
gate is MARGINAL, not a clean pass -- run longer and check whether the trend
continues.

The bounded harness self-check (used by CTest, reduced sample count) confirms
the harness discriminates the leaky sentinel from the clean one:

```
ctest --test-dir build -L timing
# or directly:
./build/tests/timing/geryon_dudect --selftest --no-pin
```

## Getting trustworthy numbers

Timing measurements are only as clean as the host. Before a real run:

- **Pin one core** and keep the machine otherwise idle. The harness pins to
  CPU 0 by default (`--cpu N` to choose, `--no-pin` to disable). For stronger
  isolation, boot with that core `isolcpus`-reserved or launch under
  `taskset -c N`.
- **Disable frequency scaling** so turbo and idle states do not add inter-class
  noise:

  ```
  sudo cpupower frequency-set -g performance
  ```

  The harness reads and warns about the cpu0 governor at startup.
- Prefer bare metal over a VM; virtual counters and steal time inflate the
  variance.

`--samples`, `--reps`, `--crop-lo`, and `--crop-hi` tune the run; see
`--help`. A target that lands INCONCLUSIVE just needs more samples.
