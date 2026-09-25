/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_PERS_H
#define GY_QSPGS_PERS_H

#include <stddef.h>
#include <stdint.h>

/*
 * skpers: the QSPGS "personal" (registration-anchoring) signature (QSPGS_SPEC.md
 * section 2.2, D-QGS-6 item 2).  The paper's PKI-bound
 * (skpers, vkpers) pair is instantiated, per [CFG+] footnote 7, by the hybrid
 * identity's OWN signing capability: the SAME XEdDSA + ML-DSA dual signing used
 * for prekeys and SAKs (both schemes required, both-or-abort), so no
 * identity-anchored QSPGS object drops to classical-only authentication.  No new
 * key is introduced; this is the recorded exception to the
 * identity-keys-sign-prekeys-only rule (CLAUDE.md, D-QGS-6 / D-QGS-9).
 *
 * It signs exactly two objects, each under its own frozen context string
 * (qspgs_labels.h): (vkbase, acq) at RegisterUser, and (UID, uk, GID) inside
 * the invite acceptance.  This module is the dual-scheme sign/verify PLUMBING
 * over caller-supplied object bytes plus a context purpose; the objects' exact
 * byte layouts are a D-QGS-7 item and are not fixed here.
 *
 * Domain separation follows the custodian's hybrid-cert convention exactly: the
 * gy_info(suite_id, ctx_purpose) string is PREPENDED to the message for the
 * XEdDSA half and passed as the FIPS 204 context for the ML-DSA half (D-PQ-1),
 * so the suite string binds into both signatures.  ctx_purpose must be one of
 * the GY_QSPGS_CTX_* labels.
 */

/* Signature buffer maxima (the hybrid 448 tier sets them; see suite.h). */
#define GY_QSPGS_PERS_ED_SIG_MAX 114     /* XEd448 signature. */
#define GY_QSPGS_PERS_MLDSA_SIG_MAX 4627 /* ML-DSA-87 signature. */

/*
 * Largest object skpers signs: (vkbase, acq) = GY_KR87_VKB (5920) + 2*kappa
 * (56).  Callers pass the pre-serialized object; a larger object is rejected
 * (GY_ERR_TOOLONG).
 */
#define GY_QSPGS_PERS_OBJ_MAX 6144

/*
 * Sign obj[0..objlen) under ctx_purpose with the hybrid identity's dual
 * capability.  curve_sk / mldsa_sk are the identity's XEdDSA and ML-DSA secret
 * keys.  On GY_OK, ed_sig (>= GY_QSPGS_PERS_ED_SIG_MAX) and mldsa_sig (>=
 * GY_QSPGS_PERS_MLDSA_SIG_MAX) hold the two signatures.  Returns GY_ERR_ARG on
 * a NULL argument, a non-hybrid suite, or an unknown ctx_purpose;
 * GY_ERR_TOOLONG if objlen exceeds GY_QSPGS_PERS_OBJ_MAX.
 */
int gy_qspgs_pers_sign(uint8_t suite_id, const uint8_t *curve_sk,
                       const uint8_t *mldsa_sk, const char *ctx_purpose,
                       const uint8_t *obj, size_t objlen, uint8_t *ed_sig,
                       uint8_t *mldsa_sig);

/*
 * Verify both signatures over obj[0..objlen) under ctx_purpose against the
 * identity's public keys.  BOTH must verify: returns GY_OK only when the XEdDSA
 * AND the ML-DSA signature pass, GY_ERR_VERIFY if either fails, and GY_ERR_ARG /
 * GY_ERR_TOOLONG as for the signer.  There is no single-signature accept path.
 */
int gy_qspgs_pers_verify(uint8_t suite_id, const uint8_t *curve_pk,
                         const uint8_t *mldsa_pk, const char *ctx_purpose,
                         const uint8_t *obj, size_t objlen,
                         const uint8_t *ed_sig, const uint8_t *mldsa_sig);

#endif /* GY_QSPGS_PERS_H */
