# geryon test suite

CTest-registered tests, one executable per `tests/<layer>/test_*.c`.  Build tiers
and the `GY_TEST_HOOKS` / `GY_PRODUCTION_BUILD` interlock are described in
`tests/CMakeLists.txt`; checked-in known-answer vectors are in
`tests/vectors/README.md`.

## Hybrid negative-test traceability (HYBRID_SPEC §11.3)

Every item of the §11.3 negative list, verbatim, mapped to the named test(s)
that implement it.  These are cross-referenced here, not duplicated.  `file::TEST`
names the `TEST(...)` case.

Both hybrid tiers: every hybrid test cited in the §11.3 and §11.4 tables runs
under BOTH geryon_h25519_512 and geryon_h448_1024.  Each `main()` loops the two
hybrid suite ids and re-runs its whole case list under a file-global descriptor
(D-GEN-7 suite genericity; the per-suite banner is printed as `== suite ... ==`),
so a single row's tests cover both tiers rather than needing a second file.  The
sole tier-specific assertions are wire-size KATs, branched per tier in place
(e.g. the initiator-prefix length 4508 vs 9004, the encoded-key sizes, and the
§7.6 header lengths).

| # | §11.3 negative item | Named test(s) |
|---|---------------------|---------------|
| 1 | Tampered signatures, each scheme separately (verify the diagnostic codes) | `kex/test_hybrid_prekeys.c::dual_signature_matrix` (GY_DIAG_CLASSICAL/PQ/BOTH_FAILED) |
| 2 | Tampered KEM ciphertexts (implicit rejection, no oracle) | `kex/test_hybrid_x3dh.c::corrupt_ct_implicit_rejection` |
| 3 | Tampered headers and flags (AEAD failure, no state mutation) | `ratchet/test_hybrid_double_ratchet.c::tamper_matrix`, `::missing_ek_rejected`, `::bad_enc_header_len_rejected`; `session/test_recv.c::uniform_failure` |
| 4 | Interval outside signed bounds | `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate` (interval 50 > advertised max 20); `kex/test_hybrid_prekeys.c::flags_matrix` |
| 5 | aead_id outside the responder's advertised set | `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate` (aead_id 4 undefined; aead_id 2 defined-but-unadvertised) |
| 6 | Reserved bits set | `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate`, `::tamper_matrix` (hybrid_flag reserved bit); `ratchet/test_hybrid_double_ratchet.c::reserved_flag_rejected` |
| 7 | Cross-suite initial messages | Full 4x4 of {c25519, h25519_512, c448, h448_1024}, incl. classical<->hybrid both ways: `api/test_suite_matrix.c::cross_suite_matrix` (each suite's bundle and initial message presented to every other suite via `gy_initiate`/`gy_receive`, rejected before any cryptographic processing: structural `GY_ERR_STATE`/`GY_ERR_ARG` on the send/initiate path, the uniform `GY_ERR_VERIFY` (D-SES-6.2) on the oracle-sensitive receive path) at the public API; `proto/test_cross_suite_seam.c::cross_suite_seam` (`gy_frame_check`, `gy_bundle_parse`/`gy_hybrid_bundle_parse` -> `GY_ERR_STATE` at the suite_id gate) at the parse seam. Same-suite reject also in `proto/test_envelope.c::envelope_negatives` (looped {c25519, c448}); `session/test_records.c::sessionid_cross_suite_rejected` |
| 8 | Cross-version initial messages | `proto/test_envelope.c::envelope_negatives` (bad outer version; inner/outer version mismatch) |
| 9 | confirm_ct outside the responder's first chain | `ratchet/test_hybrid_confirm.c::bit9_from_initiator_rejected`, `::bit9_on_later_chain_rejected`, `::truncated_confirm_rejected` |
| 10 | Replayed initial message: base-key dedupe (no new session; replayed first message undecryptable) | `session/test_recv.c::dedupe_resend`; `api/test_scenarios.c::replay_rejected`; `ratchet/test_hybrid_confirm.c::replay_undecryptable` |
| 11 | Attacker-continued replay dying at the confirmation | `ratchet/test_hybrid_confirm.c::replay_undecryptable`, `::confirmed_requires_verified` |
| 12 | Re-initiation with a fresh EK_A accepted while sessions exist | `session/test_send.c::reinitiate_demotes`; `api/test_scenarios.c::orphan_reinitiate`, `::racing_initiation_converges` |
| 13 | MAX_SKIP overflow | `ratchet/test_skipped.c::max_skip_overflow_is_noop` |
| 14 | Zeroization checks on teardown | `ratchet/test_hybrid_double_ratchet.c::zeroize`; `ratchet/test_skipped.c::teardown_zeroization`; `ratchet/test_hybrid_confirm.c::confirm_material_zeroized`; `session/test_records.c::session_free_zeroizes`; `session/test_lifecycle.c::delete_device_zeroizes` |

## Hybrid interop property tests (HYBRID_SPEC §11.4)

| # | §11.4 property | Named test(s) |
|---|----------------|---------------|
| 1 | Both parties derive identical SK and chains across OPK / no-OPK | `kex/test_hybrid_x3dh.c::interop_with_opk`, `::interop_without_opk` (assert the full seed triple sa == sb, which seeds both DR chains) |
| 2 | Every legal interval: boundary values {1, min, max, 100} plus a sampled sweep | `ratchet/test_hybrid_double_ratchet.c::ping_pong_interval1` (floor), `::ping_pong_interval100` (ceiling), `::ping_pong_interval2`, `::ping_pong_interval20`, `::interval_sweep` (sampled 1..100); negotiation bounds rejected in `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate` |
| 3 | Out-of-order delivery within MAX_SKIP | `ratchet/test_hybrid_double_ratchet.c::out_of_order`, `::dropped_across_refresh`; `ratchet/test_skipped.c::out_of_order_same_chain`, `::out_of_order_cross_epoch` |

Notes:

- The compound §11.3 sentence is split into discrete rows (10/11 are its two
  replay clauses; 7/8 its two "cross-*" clauses).
- Item 5's defined-but-unadvertised case (aead_id 2 while the SPK advertises only
  aead 1) was the one clause without a dedicated assertion before the matrix
  audit; it was added to `bad_hybrid_flag_initiate` during that audit.
- The hybrid two-party simulator (`tests/harness/gy_sim`, `gy_sim_hybrid_*`)
  drives a full hybrid handshake + confirmation + ratchet through the harness and
  provides a consolidated per-field tamper matrix (`gy_sim_hybrid_corrupt`:
  mlkem_ek, kem_ct, hybrid_flag on the initial message; confirm_ct on the reply),
  exercised by `ratchet/test_hybrid_sim.c`.
- `ratchet/test_hybrid_soak_slow.c` (`slow`) is the >= 10^4-message randomized
  hybrid soak: bidirectional, seeded reorder/drop/dup crossing ML-KEM refresh
  boundaries and the confirmation chain, seed printed for reproducibility.
- §11.2 spec-derived KATs (construction and frame vectors) are pinned in
  `tests/vectors/` and documented in `tests/vectors/README.md`.

## c448 negative matrix traceability

The classical 448 tier (geryon_c448: X448 + XEd448, SHA-512).  Every negative
of the tier mapped to the named test(s) that implement it.  Because the M1
genericity payoff routes every layer above core through the suite descriptor,
most rows are the existing classical property suites run a second time under the
c448 descriptor (the classical suites loop `{c25519, c448}` in place), not new
files; the few tier-specific tests are named explicitly.  `file::TEST` names the
`TEST(...)` case.

| # | 448 negative item | Named test(s) |
|---|-------------------|---------------|
| 1 | Tampered XEd448 signature, bundle rejected before DH (op-counter zero) | `kex/test_x3dh_c448.c::uniform_error` (corrupt SPK sig -> `GY_ERR_VERIFY`, `gy_kex_ctr.dh == 0`); primitive-level `core_hooks/test_xed448.c::tamper_matrix_rejected` |
| 2 | Non-canonical s (and non-canonical u) | `core_hooks/test_xed448.c::tamper_matrix_rejected` (57th s byte nonzero; all-ones u >= p) |
| 3 | Invalid/low-order 448 point at ingress: bundle | `kex/test_x3dh_c448.c::small_order_responder`, `::small_order_initiator` (SPK/IK/EK set to the zero point, bundle re-signed valid -> `GY_ERR_WEAK_KEY`) |
| 3 | Invalid/low-order 448 point at ingress: initial message / core | `core/test_x448.c::low_order_rejected`; `ratchet/test_zeroize.c::x3dh_initiate_deletes_ek_on_failure` (all-zero point, failure-path EK deletion) |
| 4 | All-zero DH rejection (D-X3DH-8 at 448) | `kex/test_x3dh_c448.c::small_order_responder`, `::small_order_initiator` (`GY_ERR_WEAK_KEY` before session establishment) |
| 5 | Tampered header/ciphertext, complete-state no-op | `ratchet/test_he_props.c::dr_frame_tamper_matrix`; `ratchet/test_skipped.c::forged_message_is_noop`; `session/test_recv.c::uniform_failure` (looped under c448) |
| 6 | Cross-suite / cross-version initial message | `kex/test_x3dh_c448.c::cross_suite_rejected` (suite byte flipped -> `GY_ERR_STATE` before DH), `::parse_negatives` (bad version -> `GY_ERR_ARG`); `proto/test_envelope.c::envelope_negatives` (looped); c448 as one row of the full 4x4 in `api/test_suite_matrix.c::cross_suite_matrix` and `proto/test_cross_suite_seam.c::cross_suite_seam` (c448 bundle/message to every other suite and back) |

### c448 property tests

| # | Property | Named test(s) |
|---|----------|---------------|
| 1 | Same-inputs-same-bytes determinism, RNG seams fixed (D-DR-11) at 448 | `ratchet/test_double_ratchet.c::determinism` (looped under c448) |
| 2 | MAX_SKIP boundary | `ratchet/test_skipped.c::max_skip_overflow_is_noop` (looped under c448) |
| 3 | HE no-stable-identifier scan at 448 frame sizes | `ratchet/test_he_props.c::no_stable_identifier` (looped under c448, 84-byte enc_header) |
| 4 | Randomized reorder soak, >= 10^4 messages, seeded (`slow`) | `ratchet/test_soak_slow.c::reorder_soak` (`SOAK_N == 10000`, looped under c448) |

Notes:

- The DR-step remote ratchet key (header-ingress low-order) is covered
  transitively by the X448 primitive (`DH(k, 0) = 0` -> weak-key) plus the
  X3DH-ingress low-order rows above; neither the c448 nor the c25519 tier carries
  a dedicated DR-layer low-order assertion, so this stays at parity rather than
  adding a 448-only case.
- Every row runs under ASan/UBSan in CI; the soak row is in the `slow` label.
