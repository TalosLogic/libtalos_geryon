# Cross-Cutting Decisions

**Scope:** decisions that apply to every protocol layer and suite.
Register conventions and the full index live in [README.md](README.md).

### D-GEN-1: Wire format versioning

- **Spec gap:** neither X3DH nor the Double Ratchet defines a wire
  format at all; everything about framing is implementer-defined.
- **Decision:** every top-level wire object (prekey bundle, initial
  message, DR message) begins with a version byte (0x01) and a suite ID
  byte. Multi-byte integers are big-endian. No padding on the wire.
  Reserved fields and flag bits are zero on send, verified zero on
  receive. Suite ID bytes and KDF suite names (D-GEN-3):

  | Suite | ID byte | KDF suite name |
  |-------|---------|----------------|
  | geryon_c25519 | 0x01 | c25519 |
  | (reserved) | 0x02 | |
  | geryon_c448 | 0x03 | c448 |
  | (reserved) | 0x04 | |

  Classical suites take the odd bytes so tier ordering reads from the
  ID; 0x02 and 0x04 are reserved for future suites. 0x00 is reserved
  (never a valid suite).
- **Rationale:** the wire format is versioned from day one (a
  non-negotiable design rule); the version byte is also what makes
  future changes (for example header-encryption details) deployable
  without a flag day.
- **Validation:** cross-version and cross-suite messages must be
  rejected before any cryptographic processing (negative tests).
- **Amendment (2026-07-05, envelope message type):** transport
  messages cross the proto/ boundary in a one-byte-typed envelope
  realizing D-SES-6's structural initiation detection:
  version || suite_id || msg_type || complete inner frame, where
  msg_type is 0x01 (X3DH initial message, D-X3DH-15) or 0x02 (DR
  message, D-DR-16); all other values are reserved and rejected
  before any cryptographic processing. The inner frame keeps its
  own version/suite bytes, which MUST equal the outer pair (same
  complete-frame pattern and rationale as D-DR-16's embedded first
  message; a type byte is required because a DR frame's hdr_salt
  is random and cannot be structurally distinguished from an
  initial message's fields). Prekey bundles are fetched objects,
  not transport messages, and carry no msg_type.

### D-GEN-2: Key identifiers (PKID)

- **Spec gap:** X3DH §4.13 says identifiers may be "a hash of the
  public key, a random value, or sequential values", with collision
  behavior left to the implementer.
- **Decision:** PKID = first 4 bytes of the suite hash over the encoded
  public key (curve_type || curve_pk). Treated as opaque bytes on the
  wire; loaded as a native uint32 for in-memory lookup. PKIDs are never
  security-bearing: any PKID match falls back to full-key comparison
  before use, and OPK-presence checks against zero use constant-time
  comparison.
- **Rationale:**
  1. Deterministic truncated hashes as key identifiers are grounded in
     existing crypto practice: the payment industry has used key check
     values (truncated cryptographic function of the key) for key
     identification for decades.
  2. 4 bytes converts to a single uint32, so searching key stores
     (skipped message keys, OPK tables, session lookup by ratchet key)
     is a one-instruction integer comparison instead of a memcmp
     across a byte array. Hot paths like skipped-key trial on every
     incoming message benefit directly.
  3. Deterministic derivation lets any party independently verify an
     identifier, unlike random or sequential IDs.
- **Collision/grinding note:** 2^32 space; birthday collisions at
  ~65k keys and adversarial grinding are handled by the
  never-security-bearing rule plus full-key fallback, and bundle
  validation recomputes PKIDs (D-X3DH-14). Where the wire
  carries ONLY an identifier and no key to fall back to (SPK/OPK
  references in the initial message), the key owner enforces
  store-local PKID uniqueness at generation time instead
  (D-X3DH-10).
- **Zero sentinel:** PKID 0x00000000 is reserved to mean "absent"
  (e.g. no OPK in a bundle or initial message, checked with a
  constant-time compare). Key generation regenerates any key whose
  PKID computes to zero, and validation rejects zero PKIDs on
  present keys; this makes the sentinel an invariant rather than a
  convention.
- **Validation:** PKID recomputation in bundle validation tests;
  collision-behavior test (two keys forced to share a PKID must still
  resolve correctly via full-key comparison).

### D-GEN-3: KDF info strings / domain separation

- **Spec gap:** X3DH takes `info` as an application parameter; the DR
  spec leaves KDF context choices open.
- **Decision:** every KDF binds `"geryon" . protocol_version .
  suite_name . purpose`. For HKDF this is the info parameter; for
  SP 800-108 KDF-CTR it is the Label. Domain separation never relies
  on input lengths.
- **Rationale:** explicit parameter binding; suite and version
  separation as an unconditional property rather than a consequence of
  key sizes. A single fixed app string would require a
  peers-must-match coordination warning; folding version and suite
  into the string turns that coordination problem into a structural
  guarantee.
- **Validation:** cross-suite transcript non-collision KATs.

### D-GEN-4: Private key storage

- **Spec gap:** not addressed by the specs.
- **Decision:** private keys are never serialized for transmission.
  At-rest storage goes through the application's store callbacks;
  when the library serializes for storage it requires authenticated
  encryption under a KDF-stretched key, and zeroizes plaintext copies
  (secure_zero) immediately.
- **Rationale:** zeroization is treated as protocol behavior, not
  cleanup hygiene.
- **Validation:** zeroization checks on teardown (existing test
  requirement).

### D-GEN-5: Toolchain and test harness

- **Spec gap:** the specs say nothing about build system or test
  tooling; the project must fix an engineering baseline.
- **Decision:** CMake (>= 3.22) + CTest. libsodium (pinned 1.0.22) is
  built from its submodule via `ExternalProject_Add` (autotools,
  static, `--disable-shared --with-pic`) and linked PRIVATE into the
  `geryon_core` static library. monocypher (pinned 4.0.3) is compiled
  directly as a one-file static target exposing only
  `crypto_x25519_to_eddsa`; its SHA-512 and ed25519 units stay off.
  Tests use in-house minimal macros (`tests/gy_test.h`), no
  third-party test framework, one CTest executable per
  `tests/core/test_*.c`; iterated/slow vectors carry the `slow` label
  and are excluded with `ctest -LE slow`. Both gcc and clang are
  supported and warnings are errors (`-Wall -Wextra -Werror -Wshadow
  -Wvla -Wwrite-strings -Wstrict-prototypes`). `.clang-format` is
  used at the repo root; a `format-check` target runs
  `clang-format --dry-run --Werror` over `src/ tests/ include/`,
  excluding `third_party/`.
- **Rationale:** keep test-tooling licensing trivial (no external
  framework); pin every dependency for reproducible, clean-room
  builds.
- **Validation:** fresh clone + submodule init + `cmake -B build` +
  build succeeds warning-free under gcc and clang; `ctest` runs;
  format-check flags a misformatted file.

### D-GEN-6: External oracle scope (spec-prescriptive behavior only)

- **Spec gap:** the specs do not define a validation strategy.
  An earlier plan considered a test-only "compat parameterization"
  (Signal info strings and Signal KDF_CK constants compiled into
  geryon's protocol code) so X3DH SK and root/chain/message keys
  could compare byte-exact against libsignal. Bringing up the oracle
  falsified the premise: libsignal itself deviates from the XEdDSA spec
  (D-XED-11), so byte-compatibility and spec-correctness are not
  always jointly achievable, and geryon already diverges from
  libsignal by deliberate decision (KDF_CK, D-DR-2; AEAD selection
  and per-message key/nonce derivation, D-DR-3; info strings,
  D-GEN-3; EncodeEC, D-X3DH-1).
- **Decision:** external oracles validate geryon ONLY where the
  governing spec is prescriptive (no implementer choice) and geryon
  implements the prescribed behavior. Where the oracle itself
  deviates from the spec, vectors are restricted to the agreeing
  subset (sign-bit-0 XEdDSA vectors, D-XED-11). No compat
  parameterization, ever: geryon never compiles alternate constants
  or code paths to emulate another implementation, in tests or
  otherwise. Where geryon's behavior is an implementer choice,
  validation comes from official standards vectors (RFC 7748/8032,
  RFC 5869/4231, SP 800-108, NIST ACVP), spec-derived self-KATs,
  and property tests.
- **Rationale:** a compat parameterization validates a configuration
  that never ships while the production path gains no coverage from
  it, and it doubles the KAT surface for zero shipped assurance.
  Oracle effort concentrates where an oracle is decisive: fixed
  compositions such as X3DH's DH ordering, F prefix, and zero salt,
  which a test can recompute from oracle-emitted keys through
  geryon's own core/ primitives (the oracle's info string is KAT
  input data to the HKDF wrapper, not a geryon parameterization).
- **Validation:** the oracle bring-up determines which prescriptive
  intermediates libsignal can emit (handshake private keys plus SK
  is the useful minimum); anything it cannot emit is dropped, not
  approximated.

### D-GEN-7: Suite descriptor and closed suite set

- **Spec gap:** the specs parameterize over curve and hash but say
  nothing about how an implementation organizes multi-suite
  support. geryon holds itself to "no 25519-specific constant
  outside the descriptor".
- **Decision (descriptor):** a `static const` table of
  `struct gy_suite_desc` in core/ (`suite.{c,h}`, beside encode.c),
  one row per enabled suite, looked up by
  `gy_suite_desc(suite_id)` (NULL on unknown). Each row carries:
  identity (suite_id, curve_type, KDF suite name); sizes (curve
  pk/sk, DH output, signature, hash, X3DH F prefix); curve ops
  (keypair, dh, sign, verify); tier hash/KDF ops (hash, hmac,
  hkdf_extract, hkdf_expand), the multi-input ops taking iovec-style
  `struct gy_iov` scatter/gather arrays (D-X3DH-7's no-concatenation
  rule, made generic over suites). The descriptor reserves further
  component fields (zero/NULL in the classical rows) so the full row
  shape exists up front and later suites fill them in rather
  than reshaping. SP 800-108 KDF-CTR (D-DR-2) is implemented once,
  generically, over the row's hmac; it is not a per-suite pointer.
  Callers size buffers with compile-time maxima (GY_CURVE_PK_MAX 56,
  GY_HASH_MAX 64, GY_SIG_MAX 114, GY_F_MAX 57) and operate on the
  row's lengths; no dynamic allocation. AEAD is deliberately NOT in
  the descriptor: D-DR-3 makes it a per-session runtime selection,
  dispatched by aead_id in aead.c. PKID length (4, D-GEN-2) and
  MAX_SKIP (per-protocol-version, D-DR-11) are suite-invariant and
  stay out.
- **Decision (closed set):** the suite set is CLOSED; no registration
  API, no policy knob, no runtime path admits a new suite. Extension
  requires a new register decision, a new suite ID byte and KDF suite
  name, and a protocol-version review. A "policy knob" beside the
  suite table was rejected: suite choice IS the knob, and a policy
  dimension beside the suite table reintroduces the a-la-carte surface
  the closed set exists to kill. If a real deployment ever justifies a
  new pairing, it enters as a NAMED suite through this register: one
  descriptor row, additive on the wire, no migration.
- **Rationale:** one rodata table makes the no-25519-literal rule
  mechanically checkable (review kex/ and ratchet/ for any literal
  size or direct primitive call); function pointers in a
  `static const` array are not a writable hijack surface; dispatch
  keys on the public suite ID, so no constant-time concern.
- **Validation:** table self-consistency test (each row's sizes
  equal the provider constants, e.g. crypto_scalarmult_BYTES);
  unknown-suite and NULL-op rejection tests; review-time grep for
  25519-specific literals in kex/ and ratchet/.

### D-GEN-8: Thread-safety and re-entrancy contract

- **Spec gap:** none of the Signal specifications addresses
  concurrency; a public C API must still pin a contract.
- **Decision:** geryon is thread-compatible, not thread-safe.
  After gy_init (idempotent, callable from any thread; wraps
  sodium_init), the library holds no global mutable state, takes
  no locks, and creates no threads. Every operation reads and
  writes only the objects passed to it: distinct objects
  (sessions, stores, key material) may be used concurrently from
  different threads; concurrent use of the SAME object requires
  caller serialization. Store and clock callbacks (D-SES-7/10)
  execute synchronously on the calling thread and must not
  re-enter the library on the objects of the in-flight operation
  (documented contract; debug builds assert via an in-operation
  flag). RNG is libsodium randombytes, thread-safe by
  construction.
- **Rationale:** locking policy belongs to the application; a
  crypto library's hidden mutexes are wrong for some caller and
  invisible to all. D-SES-10's staging model already confines
  mutation to a single commit point, making caller serialization
  sufficient and cheap to reason about. Matches libsodium's own
  convention, so the combined contract is uniform.
- **Validation:** API review; ThreadSanitizer test running
  concurrent independent sessions; debug-build re-entrancy
  assertion test from a store callback.

### D-GEN-9: Release versioning policy

- **Spec gap:** not a protocol matter; the project needs a shared
  release scheme.
- **Decision:** semantic versioning. The release progression is:
  - **v0.1.0** - the first releasable artifact (classical 25519,
    header encryption, full session management), 0.x signaling the
    API may still move.
  - **v0.1.1** - a patch release: no new library code and no breaking
    API change, so a PATCH bump, not a major.
  - **v1.0.0** - key custody: the API-establishing and ABI-freeze
    event. D-CUST-1 makes handle-based key custody the public surface
    (all existing APIs route behind it) and finalizes the stored-blob
    format, so the freeze belongs here. A deliberate, one-time
    breaking change.
  - Each later suite is additive on the API (a new suite constant;
    the surfaces are reserved as of v0.1.0), hence a semver MINOR,
    not a break.
  - Patch releases for fixes as needed. Tagging itself is always the
    user's call.
- **Version independence:** the library version is independent of
  the wire `protocol_version` (0x01, and v1 mandates HE). A
  wire-breaking change would force both a protocol_version bump and a
  library MAJOR; none is planned.
- **Freeze timing:** the ABI freeze is at v1.0.0, the key-custody
  release (D-CUST-1). Freezing earlier would have declared stability
  one deliberate breaking change (custody) too early; deferring the
  freeze to the custody release makes 1.0.0 mean "the public surface
  you will live with". Custody wraps the v0.1.0 surface behind handles
  rather than reshaping the protocol, so later suites stay
  API-additive from v1.0.0; a future breaking change would force 2.0.0
  per semver.
- **Validation:** CHANGELOG reviewed at each release; version macros
  asserted by a build test.

### D-GEN-10: dudect timing-target methodology

- **Spec gap:** the dudect harness leaves the framing of
  each target to the target author; two framing choices materially
  change whether |t| measures a real leak or an artifact.
- **Not-gaming litmus:** a target-framing change is legitimate ONLY
  if it does not weaken the test's power to detect a real
  key-dependent leak. Removing non-cryptographic asymmetry between the
  classes is fair; anything that could let a genuinely key-dependent
  implementation pass is gaming. Rejected as gaming: widening the crop
  to discard the samples that show an effect; cutting the sample
  count; or making class B use a fixed secret too (that destroys the
  test -- a fixed-vs-fixed split cannot detect key dependence at all).
- **Decision (three rules for every timing target):**
  1. **Tag/MAC-rejection targets are forgery-vs-forgery, never
     valid-vs-corrupt.** Encrypt-then-MAC AEAD (and the DR frame)
     does strictly more work on the accepting path (it runs the
     stream cipher to produce plaintext) than on the rejecting path,
     so a valid-vs-corrupt class split shows a large |t| on every
     platform. That is an accept-vs-reject difference on a PUBLIC
     distinction, not a secret leak. The property under test is that
     among forgeries the reject time does not depend on WHERE the tag
     mismatches (padding-oracle-style early-exit compare), so both
     classes are forged and differ only in the flipped tag-byte
     position. Applies to `aead_tag_reject` and `dr_tag_reject`
     (the latter first registered as D-DR-18).
  2. **Fixed class-A secrets are a single random-looking draw, not a
     repeated constant byte.** An all-`0xNN` key gives class A zero
     input variance and a degenerate Hamming weight; measured against
     the full-entropy class B on a DVFS-sensitive core that alone can
     inflate |t| through data-dependent frequency/power with no
     control-flow leak. Applies to `kdf_ctr`, `xeddsa_sign`, and
     `x25519`.
  3. **Both classes do identical non-cryptographic setup work.** The
     class-A/class-B split must isolate the SECRET as the only
     difference the primitive sees. In particular both classes draw
     from the RNG every trial (class A then overwrites the draw with
     its fixed secret); otherwise only class B pays the RNG cost,
     which perturbs the cache/predictor/frequency state the next
     measured window inherits -- so |t| partly reflects "did we just
     call the RNG," not the secret. This adds work to the fixed
     (previously faster) class, so it cannot manufacture a pass; and
     class B still varies its secret every trial, so leak detection is
     unchanged (satisfies the litmus). Applies to `kdf_ctr`,
     `xeddsa_sign`, and `x25519`.
- **Reading a result:** judge by the shape of the running |t|, not
  the final number. Under the null |t| is a bounded random walk
  (wanders, mean-reverts, roughly within a few units); a real effect
  grows ~sqrt(N) (monotone climb). A steady climb below the |t| < 10
  gate is MARGINAL, not a clean pass.
- **History (2026-08-05, clang17/macos):** while investigating a
  marginal `kdf_ctr` (and a raw-HMAC baseline that climbed to |t|=7.28
  on a single run), a fixed-vs-fixed control on the same branch-free
  HMAC stayed flat and mean-reverting (~1.0 down to 0.35, ended 0.83).
  A flat fixed-vs-fixed control alongside a climbing fixed-vs-random
  target localizes the climb to the fixed-vs-random asymmetry (rule 3
  above) rather than key-value dependence, which also exonerates
  compiler codegen (a key-value effect would climb the control too).
  sandybridge/clang19 was flat throughout and is the reference
  CT-validation platform. The temporary probe targets were then
  removed: they only exercised libsodium, which geryon already
  treats as the constant-time authority, and rule 3 addresses the
  asymmetry they diagnosed directly in the real targets. No geryon
  code defect was found.
- **Validation:** the two sentinels gate the harness itself; the
  real targets run nightly/manually, outside the merge gate.
