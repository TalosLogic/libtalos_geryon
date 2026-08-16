/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_RATCHET_H
#define GY_RATCHET_H

/*
 * Layer 3 (ratchet/) re-export header.  Layer 4 (session/)
 * includes THIS header only, never a kex/ or core/ header directly: ratchet/
 * re-exports the interfaces the session layer needs to build and drive
 * sessions.  Those are the Double Ratchet state and entry points
 * (double_ratchet.h) plus, through it, the kex/ types session/ operates on:
 * the X3DH seed triple and handshake entry points (x3dh.h), the prekey/key
 * structures, bundle validation and fingerprints (prekeys.h), and the
 * re-exported core utilities, wire encoding, suite descriptor, and error
 * codes (kex.h).  double_ratchet.h already pulls in header.h, he.h, and
 * x3dh.h (which includes prekeys.h -> kex.h), so this header is that single
 * include; the explicit list documents intent and survives any future
 * narrowing of the transitive graph.
 */

#include "double_ratchet.h" /* gy_dr_state, gy_dr_init_*, encrypt/decrypt */
#include "prekeys.h"        /* gy_keypair, gy_public_key, bundle, fingerprint */
#include "x3dh.h"           /* gy_dr_secrets, gy_x3dh_initiate/respond */

#endif /* GY_RATCHET_H */
