/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS group-structure wire KAT vectors, self-generated
 * (D-QGS-10).  RE-CUT 2026-09-16 for D-QGS-13 E1: the appendix-line
 * TBS now binds the apx-hdr (GID || vMaj || vMin) ahead of the line,
 * so GY_QW_KAT_APX_TBS was deliberately regenerated at
 * format_version 1 (v1.5.0 is untagged; nothing consumed the old
 * bytes).  Otherwise pinned to geryon's reading of the [CFG+]
 * 2026/453 preprint; not regenerated on refactor.  A further re-cut
 * is a deliberate D-QGS-12 format_version event.
 */

#ifndef GY_QSPGS_WIRE_KAT_H
#define GY_QSPGS_WIRE_KAT_H

#define QSPGS_WIRE_KAT_POPULATED 1

#define GY_QW44_KAT_CUID                                                       \
    "03bff68ebfcf55434796fcc9508c6fd8aebb35edeceb4e03917f70e69f31f9ad"
#define GY_QW44_KAT_VKHASH                                                     \
    "f7b9e91bf2304e114cc098973d552b27b6a23b79cd32646fc38a21fb1f1cf388"
#define GY_QW44_KAT_TBS                                                        \
    "000000000101027777777777777777777777777777777700010100000005000000083c3c" \
    "3c3c3c3c3c3c0002010220000103bff68ebfcf55434796fcc9508c6fd8aebb35edeceb4e" \
    "03917f70e69f31f9ad0100102a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a030102200001f7b9" \
    "e91bf2304e114cc098973d552b27b6a23b79cd32646fc38a21fb1f1cf388000000050000" \
    "0003"

#define GY_QW87_KAT_CUID                                                       \
    "33e115fbe276488ab1d0dbba4d214a6089d61acd61c4ecc39247b5b03edc6a1b58d38f68" \
    "59e51739743f9f0290e1c381d1c13579f274dd1732e187cd6f05f181"
#define GY_QW87_KAT_VKHASH                                                     \
    "381222fb518e1d11791f83b1dcffdaafc5d83bd8975819568501915921559d105282e7ea" \
    "1a4ab45474db034ebd7ed9b7dd941ffa53f873713a27f0d12242e421"
#define GY_QW87_KAT_TBS                                                        \
    "000000000101047777777777777777777777777777777700010100000005000000083c3c" \
    "3c3c3c3c3c3c0002010440000133e115fbe276488ab1d0dbba4d214a6089d61acd61c4ec" \
    "c39247b5b03edc6a1b58d38f6859e51739743f9f0290e1c381d1c13579f274dd1732e187" \
    "cd6f05f1810100102a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a030104400001381222fb518e" \
    "1d11791f83b1dcffdaafc5d83bd8975819568501915921559d105282e7ea1a4ab45474db" \
    "034ebd7ed9b7dd941ffa53f873713a27f0d12242e4210000000500000003"

#define GY_QW_KAT_APX_TBS                                                      \
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000002000000050200000003b0b1b2b3b4b5b6" \
    "b7b8b9babb"

#endif /* GY_QSPGS_WIRE_KAT_H */
