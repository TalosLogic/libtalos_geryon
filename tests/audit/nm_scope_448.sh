#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# 448 scope audit (D-XED-12): geryon's OWN library objects must never
# reference the RFC 8032 Ed448 scheme (decaf_ed448_sign / decaf_ed448_verify).
# Production 448 signing is XEd448 only; the RFC 8032 scheme is a DIFFERENT
# construction, called ONLY by the 448 validation-gate tests. The decaf448
# archive DEFINES those symbols (from libdecaf's eddsa.c, for the gate), so this
# does not scan decaf448 - it scans geryon's archives (geryon_core..geryon_proto)
# for an UNDEFINED reference (nm "U"), which is what a stray production call
# would produce. This gate guards the production/gate scope boundary.
#
# Usage: nm_scope_448.sh <archive> [<archive> ...]
#   Each argument is a geryon static library. Exits nonzero if any carries a
#   reference to the forbidden symbols.

set -eu

forbidden='decaf_ed448_sign|decaf_ed448_verify'
status=0

for lib in "$@"; do
    if [ ! -f "$lib" ]; then
        echo "nm_scope_448: missing archive: $lib" >&2
        exit 1
    fi
    # nm marks undefined references with "U". Match the forbidden scheme symbols
    # as whole words at end of line (decaf_ed448_sign, not _sign_prehash etc.).
    if nm "$lib" 2>/dev/null \
        | grep -E " U (${forbidden})\$" >/dev/null; then
        echo "nm_scope_448: FORBIDDEN reference to the RFC 8032 Ed448 scheme" \
            "in $(basename "$lib"):" >&2
        nm "$lib" 2>/dev/null | grep -E " U (${forbidden})\$" >&2
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "nm_scope_448: OK (no decaf_ed448 scheme references in geryon objects)"
fi
exit "$status"
