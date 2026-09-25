/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * QSPGS identity-certification constants: the two objects the hybrid identity
 * key certifies (D-QGS-6, footnote 7) and the field widths of those objects.
 *
 * The custodian holds the identity key, so it owns the definition of exactly
 * what that key may sign (X.509 KeyUsage / EKU model): it builds these two
 * objects itself from typed fields and IK-signs them, and never signs a
 * caller-supplied blob.  The QSPGS vertical needs the same widths and labels
 * for its own uses (the raw-key registration path, uk / acq / gk sizing, the
 * section 4 wire codecs), so this is the SINGLE place they are defined and both
 * sides include it: the custodian in src/proto and the whole vertical through
 * qspgs_keys.h / qspgs_wire.h / qspgs_labels.h.  It lives in core because that
 * is the only layer both the custodian (proto) and the sk-free common layer /
 * server (which must not depend on proto) can reach.  Pure integer / string
 * literals, no includes, idempotently guarded.
 */

#ifndef GY_QSPGS_CONST_H
#define GY_QSPGS_CONST_H

/*
 * skpers per-operation context strings (QSPGS_SPEC.md section 2.2, D-QGS-6
 * item 2): the domain-separation labels of the only two objects the identity
 * key signs.  As gy_info purposes these become the XEdDSA prepended-info string
 * AND the FIPS 204 ML-DSA context; the suite string is bound into both halves.
 */
#define GY_QSPGS_CTX_REGUSER "qspgs-reguser"     /* signs (vkbase, acq). */
#define GY_QSPGS_CTX_INVACCEPT "qspgs-invaccept" /* signs (UID, uk, GID). */

/*
 * Master user key = 2*kappa bytes per tier (QSPGS_SPEC.md section 2.2; muk
 * replaces GroupMasterKey).  This is also the uk / acq / gk width used across
 * the vertical; callers stack-allocate to the MAX and operate on
 * gy_qspgs_master_key_len(suite_id) bytes.
 */
#define GY_QSPGS_MASTER_KEY_255 32
#define GY_QSPGS_MASTER_KEY_448 56
#define GY_QSPGS_MASTER_KEY_MAX 56

/*
 * Fixed identifier widths.  UID is a single width (SEC-v1.5.0 LOW-2: a variable
 * width would leak a per-entry length class through sealed member entries); GID
 * is the derived 16-byte group id.
 */
#define GY_QSPGS_UID_LEN 16
#define GY_QSPGS_GID_LEN 16

#endif /* GY_QSPGS_CONST_H */
