#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# ctest wrapper for the independent group KVAC oracle (D-GEN-6), both tiers.
# Regenerates a fresh vector file from the geryon emitter and verifies it with
# the clean-room Python oracle.  Exits 77 (CTest "Skipped") when python3 is
# absent, or when no tier could be verified (no usable backend); per-tier
# skips (e.g. libsodium or the decaf shim missing) are reported by verify.py but
# do not fail.  So it runs opportunistically and never blocks a toolchain-less
# CI box - matching the manual-oracle convention in docs/TEST_ORACLES.md.
#
# Args: $1 = emitter binary (test_group_kvac_emit), $2 = verify.py path,
#       $3 = decaf448 shim shared lib (optional; empty -> 448 records skipped).

EMIT="$1"
VERIFY="$2"
SHIM="$3"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found; skipping group_kvac oracle"
    exit 77
fi

VEC="$(mktemp)" || { echo "mktemp failed"; exit 1; }
trap 'rm -f "$VEC"' EXIT

if ! "$EMIT" --dump > "$VEC"; then
    echo "emitter failed"
    exit 1
fi

if [ -n "$SHIM" ]; then
    python3 "$VERIFY" --decaf448 "$SHIM" "$VEC"
else
    python3 "$VERIFY" "$VEC"
fi
rc=$?
# verify.py: 0 = all verified equations pass, 1 = mismatch, 2 = nothing verified.
if [ "$rc" -eq 2 ]; then
    echo "no oracle backend available; skipping"
    exit 77
fi
exit "$rc"
