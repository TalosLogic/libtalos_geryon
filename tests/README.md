# geryon test suite

CTest-registered tests, one executable per `tests/<layer>/test_*.c`.  Build tiers
and the `GY_TEST_HOOKS` / `GY_PRODUCTION_BUILD` interlock are described in
`tests/CMakeLists.txt`; checked-in known-answer vectors are in
`tests/vectors/README.md`.

## Hybrid negative-test traceability (HYBRID_SPEC §11.3)

Every item of the §11.3 negative list, verbatim, mapped to the named test(s)
that implement it.  Most were delivered across GER-M5-05..08 and are
cross-referenced here, not duplicated (GER-M5-09 task 2).  `file::TEST` names the
`TEST(...)` case; the ticket column is the milestone that first delivered it.

| # | §11.3 negative item | Named test(s) | Ticket |
|---|---------------------|---------------|--------|
| 1 | Tampered signatures, each scheme separately (verify the diagnostic codes) | `kex/test_hybrid_prekeys.c::dual_signature_matrix` (GY_DIAG_CLASSICAL/PQ/BOTH_FAILED) | M5-05 |
| 2 | Tampered KEM ciphertexts (implicit rejection, no oracle) | `kex/test_hybrid_x3dh.c::corrupt_ct_implicit_rejection` | M5-06 |
| 3 | Tampered headers and flags (AEAD failure, no state mutation) | `ratchet/test_hybrid_double_ratchet.c::tamper_matrix`, `::missing_ek_rejected`, `::bad_enc_header_len_rejected`; `session/test_recv.c::uniform_failure` | M5-07, M5-08 |
| 4 | Interval outside signed bounds | `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate` (interval 50 > advertised max 20); `kex/test_hybrid_prekeys.c::flags_matrix` | M5-06, M5-05 |
| 5 | aead_id outside the responder's advertised set | `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate` (aead_id 4 undefined; aead_id 2 defined-but-unadvertised) | M5-06, M5-09 |
| 6 | Reserved bits set | `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate`, `::tamper_matrix` (hybrid_flag reserved bit); `ratchet/test_hybrid_double_ratchet.c::reserved_flag_rejected` | M5-06, M5-07 |
| 7 | Cross-suite initial messages | `proto/test_envelope.c::envelope_negatives` (wrong suite -> GY_ERR_STATE); `session/test_records.c::sessionid_cross_suite_rejected` | M5-08 |
| 8 | Cross-version initial messages | `proto/test_envelope.c::envelope_negatives` (bad outer version; inner/outer version mismatch) | M5-08 |
| 9 | confirm_ct outside the responder's first chain | `ratchet/test_hybrid_confirm.c::bit9_from_initiator_rejected`, `::bit9_on_later_chain_rejected`, `::truncated_confirm_rejected` | M5-07 |
| 10 | Replayed initial message: base-key dedupe (no new session; replayed first message undecryptable) | `session/test_recv.c::dedupe_resend`; `api/test_scenarios.c::replay_rejected`; `ratchet/test_hybrid_confirm.c::replay_undecryptable` | M5-08, M5-07 |
| 11 | Attacker-continued replay dying at the confirmation | `ratchet/test_hybrid_confirm.c::replay_undecryptable`, `::confirmed_requires_verified` | M5-07 |
| 12 | Re-initiation with a fresh EK_A accepted while sessions exist | `session/test_send.c::reinitiate_demotes`; `api/test_scenarios.c::orphan_reinitiate`, `::racing_initiation_converges` | M5-08 |
| 13 | MAX_SKIP overflow | `ratchet/test_skipped.c::max_skip_overflow_is_noop` | M5-07 |
| 14 | Zeroization checks on teardown | `ratchet/test_hybrid_double_ratchet.c::zeroize`; `ratchet/test_skipped.c::teardown_zeroization`; `ratchet/test_hybrid_confirm.c::confirm_material_zeroized`; `session/test_records.c::session_free_zeroizes`; `session/test_lifecycle.c::delete_device_zeroizes` | M5-07, M5-08 |

## Hybrid interop property tests (HYBRID_SPEC §11.4)

| # | §11.4 property | Named test(s) | Ticket |
|---|----------------|---------------|--------|
| 1 | Both parties derive identical SK and chains across OPK / no-OPK | `kex/test_hybrid_x3dh.c::interop_with_opk`, `::interop_without_opk` (assert the full seed triple sa == sb, which seeds both DR chains) | M5-06 |
| 2 | Every legal interval: boundary values {1, min, max, 100} plus a sampled sweep | `ratchet/test_hybrid_double_ratchet.c::ping_pong_interval1` (floor), `::ping_pong_interval100` (ceiling), `::ping_pong_interval2`, `::ping_pong_interval20`, `::interval_sweep` (sampled 1..100); negotiation bounds rejected in `kex/test_hybrid_x3dh.c::bad_hybrid_flag_initiate` | M5-07, M5-09 |
| 3 | Out-of-order delivery within MAX_SKIP | `ratchet/test_hybrid_double_ratchet.c::out_of_order`, `::dropped_across_refresh`; `ratchet/test_skipped.c::out_of_order_same_chain`, `::out_of_order_cross_epoch` | M5-07 |

Notes:

- The compound §11.3 sentence is split into discrete rows (10/11 are its two
  replay clauses; 7/8 its two "cross-*" clauses).
- Item 5's defined-but-unadvertised case (aead_id 2 while the SPK advertises only
  aead 1) was the one clause without a dedicated assertion before the matrix
  audit; it was added to `bad_hybrid_flag_initiate` under GER-M5-09.
- The hybrid two-party simulator (`tests/harness/gy_sim`, `gy_sim_hybrid_*`)
  drives a full hybrid handshake + confirmation + ratchet through the harness and
  provides a consolidated per-field tamper matrix (`gy_sim_hybrid_corrupt`:
  mlkem_ek, kem_ct, hybrid_flag on the initial message; confirm_ct on the reply),
  exercised by `ratchet/test_hybrid_sim.c` (GER-M5-09 task 4).
- `ratchet/test_hybrid_soak_slow.c` (`slow`) is the >= 10^4-message randomized
  hybrid soak: bidirectional, seeded reorder/drop/dup crossing ML-KEM refresh
  boundaries and the confirmation chain, seed printed for reproducibility
  (GER-M5-09 task 5).
- §11.2 spec-derived KATs (construction and frame vectors) are pinned in
  `tests/vectors/` and documented in `tests/vectors/README.md`.
