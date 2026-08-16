/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_KEX_H
#define GY_KEX_H

/*
 * Layer 2 (kex/) re-export header.  Layer 3 (ratchet/) includes THIS header
 * only, never a core/ header directly: kex/ re-exports the core interfaces
 * ratchet needs (suite descriptor, KDF, AEAD, RNG, wire encoding, utilities,
 * error codes).  kex/ itself includes core/ headers only; it carries no
 * 25519-specific constant and makes no direct primitive call, routing
 * everything through the suite descriptor (D-GEN-7).
 *
 * kekprot.h/pwhash.h/seal.h (D-CUST-1) ride the same chokepoint for the same
 * reason as util.h: key custody is not suite-specific crypto (no descriptor
 * dispatch applies), so it re-exports the same way the plain utilities do.
 * This makes sealing reachable from proto/ (Layer 5, which owns the
 * gy_custodian object, CUSTODY_SPEC section 14) without proto/ including a
 * core/ header directly; kex/ itself makes no sealing call.
 */

#include "aead.h"
#include "encode.h"
#include "error.h"
#include "kdf.h"
#include "kekprot.h"
#include "pwhash.h"
#include "rng.h"
#include "seal.h"
#include "suite.h"
#include "util.h"

/*
 * Test-only operation counters.  Compiled in ONLY when
 * GY_TEST_HOOKS is defined, so a bundle-validation ordering test can assert
 * that a tampered field aborts before any signature verification, and before
 * any private-key operation (D-X3DH-14).  The counter object is defined once
 * in prekeys.c under the same guard; tests recompile the kex sources with
 * -DGY_TEST_HOOKS rather than link the production library.
 */
#ifdef GY_TEST_HOOKS
#include <stdint.h>
struct gy_kex_counters {
    unsigned keypair; /* descriptor keypair generations */
    unsigned sign;    /* descriptor sign calls */
    unsigned verify;  /* descriptor verify calls */
    unsigned dh;      /* descriptor dh calls */
    unsigned hash;    /* PKID recomputations / fingerprint hashes */
};
extern struct gy_kex_counters gy_kex_ctr;
#define GY_KEX_COUNT(field) (gy_kex_ctr.field++)
#else
#define GY_KEX_COUNT(field) ((void)0)
#endif

#endif /* GY_KEX_H */
