#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Descriptor-discipline audit (GER-M1-09, D-GEN-7): the layers above core
# (kex/, ratchet/, session/, proto/) must carry NO direct call to a core
# primitive and NO suite-specific PQ size constant - everything routes through
# the suite descriptor.  GER-M5-10 widened the scan from {kex, ratchet} to also
# cover {session, proto} (the layers that gained PQ fields) and added the
# suite-specific PQ primitive-size macros to the forbidden set.  This is the
# mechanical half of the milestone exit criterion; reviewed exceptions (a
# suite-INVARIANT primitive use, e.g. the fixed SHA-512 store-key derivation)
# are recorded in the allowlist.
#
# Usage: descriptor_discipline.sh [SRC_ROOT]
#   SRC_ROOT defaults to the repository's src/ (derived from this script's
#   location).  Exits nonzero if any forbidden pattern appears outside the
#   allowlist.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=${1:-$(cd "$here/../../src" && pwd)}
allowlist="$here/discipline_allowlist.txt"

# Direct primitive calls forbidden below the descriptor: the suite-tier hashes
# and KDFs, the curve/signature ops, and any raw libsodium (crypto_*) entry
# point.  Generic core wrappers reached legitimately (gy_kdf_ctr, gy_pkid,
# gy_info, gy_encode_ec) are NOT primitives and do not match.
pattern='gy_x25519|gy_x448|gy_xeddsa|gy_xed448|gy_ed25519|gy_ed448'
pattern="$pattern"'|gy_sha256|gy_sha512|gy_hmac_sha(256|512)'
pattern="$pattern"'|gy_hkdf_sha(256|512)|crypto_[a-z]'
# Suite-SPECIFIC PQ primitive-size constants (GER-M5-10): the ML-KEM/ML-DSA
# per-parameter-set sizes (GY_MLKEM512_*, GY_MLKEM1024_*, GY_MLDSA44_*,
# GY_MLDSA87_*) belong to core's primitive wrappers only; above core, PQ sizes
# come from desc->kem_*_len / desc->dsa_*_len.  The suite-AGNOSTIC maxima
# (GY_KEM_*_MAX, GY_DSA_*_MAX) are the sanctioned buffer/array-sizing macros and
# are deliberately NOT matched.
pattern="$pattern"'|GY_MLKEM[0-9]+_|GY_MLDSA[0-9]+_'

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# grep -rn prints "<abspath>:<lineno>:<content>"; tolerate no-match (nonzero).
grep -rnE "$pattern" "$root/kex" "$root/ratchet" "$root/session" "$root/proto" \
    >"$tmp" 2>/dev/null || true

status=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    # Normalize "<root>/kex/foo.c:12:..." to the allowlist key "src/kex/foo.c:12".
    rel=${line#"$root"/}
    path=${rel%%:*}
    rest=${rel#*:}
    lineno=${rest%%:*}
    key="src/$path:$lineno"
    if grep -qxF "$key" "$allowlist" 2>/dev/null; then
        continue
    fi
    printf 'DISCIPLINE VIOLATION: %s\n' "$key" >&2
    printf '  %s\n' "${rest#*:}" >&2
    status=1
done <"$tmp"

if [ "$status" -eq 0 ]; then
    echo "descriptor-discipline: clean (kex/ ratchet/ session/ proto/ carry no"
    echo "  direct primitive call and no suite-specific PQ size constant;"
    echo "  reviewed exceptions in allowlist)"
fi
exit "$status"
