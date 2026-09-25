/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS test-only forging seams.  These exist ONLY under
 * GY_TEST_HOOKS and are compiled out of any production build (src/core/error.h
 * #errors if GY_TEST_HOOKS and GY_PRODUCTION_BUILD ever coexist), so no forging
 * entry point can enter the shipped library.  They let a test mint a GENUINE
 * KR-ML-DSA signature over caller-supplied bytes under a custodian's own group
 * pseudonym, which no public API allows: it is the only way to produce a
 * validly-signed-but-inconsistent core and thereby exercise the fetch-side
 * defenses that reject it (the D-QGS-13 E5 all-member vk-lst recompute).
 */
#ifndef GY_QSPGS_HOOKS_H
#define GY_QSPGS_HOOKS_H

#ifdef GY_TEST_HOOKS

#include <stddef.h>
#include <stdint.h>

#include "geryon_qspgs.h" /* gy_custodian, GY_QSGROUP_GID_LEN */

/*
 * Re-sign caller-supplied core wire objects (header, member-list, vk-lst) under
 * the caller's group pseudonym for group gid, emitting the core-signature object
 * into sig_out (sig_out_len: capacity in, length out).  The caller may hand a
 * TAMPERED vk-lst (for example one carrying a foreign member's H(vkpsdn) at a
 * non-signer index): this produces a core whose admin signature is genuine yet
 * whose vk-lst is inconsistent, so a test can verify gy_custodian_qsgroup_fetch
 * rejects it at the E5 all-member recompute (GY_ERR_VERIFY) rather than only at
 * the signer's own entry.  signer_index is the caller's member index and
 * last_vmin the value bound into the signature.  The caller must hold gid.
 * Returns GY_OK, or a negative GY_ERR_* (GY_ERR_NOT_FOUND if gid is unheld).
 */
int gy_custodian_qsgroup_hook_sign_core(
    gy_custodian *c, const uint8_t gid[GY_QSGROUP_GID_LEN], const uint8_t *hdr,
    size_t hdr_len, const uint8_t *member_list, size_t member_list_len,
    const uint8_t *vk_lst, size_t vk_lst_len, uint32_t signer_index,
    uint32_t last_vmin, uint8_t *sig_out, size_t *sig_out_len);

/*
 * Sign a caller-supplied appendix-line payload under the caller's group
 * pseudonym for group gid, emitting the single-line appendix object into
 * line_out (line_out_len: capacity in, length out).  Unlike the public
 * appendix-line calls, this does NOT construct or validate the payload: the
 * caller supplies arbitrary (possibly malformed) bytes, e.g. an addUser payload
 * whose C_UID' does not open to (UID', r'), so a test can verify Fetch's
 * CheckAppendixLine reports such a line invalid rather than applying it.
 * line_type is a GY_QAPX_* kind and author_index the caller's line index.  The
 * caller must hold gid.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_qsgroup_hook_sign_line(
    gy_custodian *c, const uint8_t gid[GY_QSGROUP_GID_LEN], uint32_t vmaj,
    uint32_t vmin, uint8_t line_type, uint32_t author_index,
    const uint8_t *payload, size_t payload_len, uint8_t *line_out,
    size_t *line_out_len);

#endif /* GY_TEST_HOOKS */
#endif /* GY_QSPGS_HOOKS_H */
