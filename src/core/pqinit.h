/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_PQINIT_H
#define GY_PQINIT_H

/*
 * liboqs process-global setup (D-PQ-2).  A single entry point, invoked once
 * from gy_core_init() before any ML-KEM / ML-DSA call can run, that points
 * liboqs's random-byte source at geryon's one getrandom-backed RNG
 * (gy_random_bytes, D-XED-1).  There is no per-context liboqs state:
 * OQS_randombytes_custom_algorithm sets a PROCESS-GLOBAL function pointer, so
 * registration is idempotent and benign under the D-GEN-8 one-context-per-thread
 * contract (the shim routes to libsodium, which is thread-safe).
 *
 * The registered shim ABORTS on RNG failure: the liboqs callback returns void,
 * so a failing generator cannot be signalled and liboqs would otherwise key or
 * sign over an unfilled buffer.  See pqinit.c.
 */

/*
 * Register geryon's RNG as liboqs's random-byte source.  Idempotent; must be
 * called from gy_core_init() before any PQ primitive is used.  Returns GY_OK.
 */
int gy_pq_init(void);

#ifdef GY_TEST_HOOKS
/*
 * Test-only seams into the liboqs RNG shim (D-PQ-2 / D-PQ-3), compiled only
 * under GY_TEST_HOOKS.  Two purposes:
 *   - draw counting: proves a PQ primitive (e.g. gy_mlkem_keypair) actually
 *     draws through geryon's registered shim rather than some bypass path, on
 *     both the DIST and pure-C backends;
 *   - fault injection: forces the shim's failure branch so the death test can
 *     confirm it ABORTS rather than returning an unfilled buffer.
 * Neither is thread-safe; the tests are single-threaded.
 */

/* Bytes the shim has been asked to produce since the last reset. */
size_t gy_pq_rng_draw_count(void);
void gy_pq_rng_reset_draw_count(void);

/*
 * When set nonzero, the next shim invocation takes its failure branch
 * (abort()).  For the death test only; a normal test never sets it.
 */
void gy_pq_rng_set_force_fail(int on);
#endif /* GY_TEST_HOOKS */

#endif /* GY_PQINIT_H */
