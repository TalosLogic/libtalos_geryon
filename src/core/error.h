/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_ERROR_H
#define GY_ERROR_H

/*
 * Library-wide return codes.  Every geryon function returns int: GY_OK (0)
 * on success, a negative GY_ERR_* on failure.  A return value is never
 * silently ignored by callers.
 *
 * These numeric values are ABI-stable from day one: they may appear in
 * stored state and cross the library boundary, so existing codes are never
 * renumbered.  New codes are only ever appended with the next lower value.
 */
#define GY_OK 0               /* Success. */
#define GY_ERR_ARG -1         /* Bad argument or length. */
#define GY_ERR_CRYPTO -2      /* Underlying crypto provider failure. */
#define GY_ERR_VERIFY -3      /* Signature, tag, or comparison mismatch. */
#define GY_ERR_TOOLONG -4     /* Input exceeds a protocol length bound. */
#define GY_ERR_WEAK_KEY -5    /* All-zero DH output / degenerate key. */
#define GY_ERR_STATE -6       /* Operation invalid in the current state. */
#define GY_ERR_UNSUPPORTED -7 /* Feature unavailable (e.g. AEAD on CPU). */
#define GY_ERR_KEY_CHANGED -8 /* Peer identity key changed; accept required. */
#define GY_ERR_EXPIRED -9     /* Session past its expiration bound (D-SES-7). */
#define GY_ERR_NOT_FOUND -10  /* Custodian: unknown key handle/id. */
#define GY_ERR_NO_SPACE -11   /* Custodian: key-slot table exhausted. */

/*
 * Return a static, human-readable description of a GY_* code, for tests and
 * logging.  Never allocates; the returned pointer is valid for the process
 * lifetime.  Unknown codes yield a fixed "unknown error" string.
 */
const char *gy_strerror(int);

#endif /* GY_ERROR_H */
