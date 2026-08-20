#!/usr/bin/env bash
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Formal-model runner (CI). Executes every ProVerif model under
# formal/models/, parses its RESULT lines, and compares each query's verdict
# against the authoritative table in formal/README.md (D-FM-7). Any mismatch
# is a failure, including:
#   - "cannot be proved" anywhere (never an acceptable outcome);
#   - a query that proves where the table expects an attack (D-FM-5 direction);
#   - a query that is attacked where the table expects a proof;
#   - a per-file wall-clock overrun (cap = 2x the recorded budget), which
#     guards against non-termination.
#
# ProVerif is GPL tooling under the same carve-out as the test oracles: it is
# never linked into the library. The pinned version is 2.04 (matches the BJKS
# PQXDH analysis); the job asserts that before running anything so image drift
# fails fast and loudly.
#
# Usage: scripts/formal_check.sh
# Exit status is nonzero if any check fails.

set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
readme="$root/formal/README.md"
lib="$root/formal/lib/geryon.pvl"
pv_expect="2.04"
fail=0

note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

# ---- 0. version pin (fail-fast, before running any model) ----------------
sect "0. ProVerif version pin ($pv_expect)"
if ! command -v proverif >/dev/null 2>&1; then
    note "FAIL: proverif not on PATH (provision the runner: opam pin add proverif $pv_expect)"
    exit 1
fi
# ProVerif prints its version banner on -help (and on every run). Match the
# pinned string exactly; a mismatched prover fails here rather than silently
# producing verdicts under a different resolution strategy.
banner="$(proverif -help 2>&1 || true)"
if ! printf '%s\n' "$banner" | grep -qiE "proverif[^0-9]*$pv_expect([^0-9]|$)"; then
    note "FAIL: ProVerif $pv_expect not detected; banner was:"
    printf '%s\n' "$banner" | head -3 | sed 's/^/    /'
    exit 1
fi
note "ok: ProVerif $pv_expect"

libarg=()
[ -f "$lib" ] && libarg=(-lib "$lib")

# ---- 1. per-model verdict enforcement ------------------------------------
sect "1. model verdicts vs formal/README.md table"
if [ ! -f "$readme" ]; then
    note "FAIL: $readme missing (it is the authoritative verdict table)"
    exit 1
fi

# Pull the expected verdicts out of the README table. Rows look like:
#   | `formal/models/smoke.pv` | ... | proved | 5 | default |
# Fields (split on '|'): 2=file 3=query 4=expected 5=budget 6=config.
# Emitted as TSV: file<TAB>expected<TAB>budget, in table order.
table="$(awk -F'|' '
    /\| *`formal\/models\// {
        file = $2; verd = $4; bud = $5;
        gsub(/[` ]/, "", file);
        gsub(/^[ \t]+|[ \t]+$/, "", verd);
        gsub(/[^0-9]/, "", bud);
        if (bud == "") bud = 30;
        print file "\t" verd "\t" bud;
    }' "$readme")"

if [ -z "$table" ]; then
    note "FAIL: no model rows found in $readme table"
    exit 1
fi

# Unique model files, preserving first-seen order.
models="$(printf '%s\n' "$table" | cut -f1 | awk '!seen[$0]++')"

verdict_of() { # classify one RESULT line -> proved|attack|cannotprove|unknown
    case "$1" in
    *"cannot be proved"*) echo cannotprove ;;
    *" is true"*) echo proved ;;
    *" is false"*) echo attack ;;
    *) echo unknown ;;
    esac
}

while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    model="$root/$rel"
    if [ ! -f "$model" ]; then
        note "FAIL: $rel listed in table but not on disk"
        fail=1
        continue
    fi

    # Expected verdict sequence (table order) and the largest budget row,
    # from which the 2x wall-clock cap is derived.
    mapfile -t want < <(printf '%s\n' "$table" | awk -F'\t' -v f="$rel" '$1==f {print $2}')
    budget="$(printf '%s\n' "$table" | awk -F'\t' -v f="$rel" '$1==f {print $3}' | sort -n | tail -1)"
    cap=$(( budget * 2 ))
    [ "$cap" -lt 2 ] && cap=2

    out="$(timeout "$cap" proverif "${libarg[@]}" "$model" 2>&1)"
    rc=$?
    if [ "$rc" -eq 124 ]; then
        note "FAIL: $rel exceeded ${cap}s wall-clock cap (budget ${budget}s x2)"
        fail=1
        continue
    fi

    mapfile -t got < <(printf '%s\n' "$out" | grep '^RESULT' | while IFS= read -r line; do verdict_of "$line"; done)

    if [ "${#got[@]}" -ne "${#want[@]}" ]; then
        note "FAIL: $rel produced ${#got[@]} RESULT line(s), table expects ${#want[@]}"
        printf '%s\n' "$out" | grep '^RESULT' | sed 's/^/      /'
        fail=1
        continue
    fi

    ok=1
    for i in "${!want[@]}"; do
        if [ "${got[$i]}" != "${want[$i]}" ]; then
            note "FAIL: $rel query $((i + 1)): expected '${want[$i]}', got '${got[$i]}'"
            ok=0
        fi
    done
    [ "$ok" -eq 1 ] && note "ok: $rel (${#want[@]} query/queries at expected verdicts)" || fail=1
done <<<"$models"

sect "result"
[ "$fail" -eq 0 ] && note PASS || note FAIL
exit "$fail"
