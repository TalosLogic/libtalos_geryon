#!/usr/bin/env bash
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Layer audit (CI).  Three checks, all expected to pass with an empty
# allowlist:
#
#   1. Include direction: a source in layer N may #include local headers only
#      from its own layer or a lower one (core < kex < ratchet < session <
#      proto, plus include/geryon.h at the proto boundary).  No upward includes.
#   2. proto/ symbol hygiene (nm): the compiled proto/ objects reference no
#      symbol defined in ratchet/ or core/ (they go through session/).  Skipped
#      with a notice if a build tree is not found.
#   3. include/geryon.h compiles standalone as C++ (extern "C" guard).
#
# Usage: scripts/layer_audit.sh [build_dir]   (build_dir default: build)
# Exit status is nonzero if any check fails.

set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
build="${1:-$root/build}"
allow="$root/scripts/layer_audit.allow"
tmp="$(mktemp)"
fail=0

note() { printf '  %s\n' "$*"; }
sect() { printf '\n== %s ==\n' "$*"; }

layer_rank() {
    case "$1" in
    core) echo 1 ;;
    kex) echo 2 ;;
    ratchet) echo 3 ;;
    session) echo 4 ;;
    proto | public) echo 5 ;;
    *) echo 0 ;;
    esac
}

header_layer() {
    local base="$1" d
    for d in core kex ratchet session proto; do
        [ -e "$root/src/$d/$base" ] && { echo "$d"; return; }
    done
    [ "$base" = geryon.h ] && { echo public; return; }
    echo extern
}

# ---- 1. include direction ----------------------------------------------
sect "1. include direction"
: >"$tmp"
find "$root/src" \( -name '*.c' -o -name '*.h' \) | while IFS= read -r src; do
    fdir="$(basename "$(dirname "$src")")"
    frank="$(layer_rank "$fdir")"
    [ "$frank" -eq 0 ] && continue
    grep -oE '#include[[:space:]]+"[^"]+"' "$src" |
        sed -E 's/.*"([^"]+)".*/\1/' | while IFS= read -r inc; do
        base="$(basename "$inc")"
        ilayer="$(header_layer "$base")"
        [ "$ilayer" = extern ] && continue
        irank="$(layer_rank "$ilayer")"
        if [ "$irank" -gt "$frank" ]; then
            printf '%s: includes %s (%s > %s)\n' \
                "${src#"$root"/}" "$base" "$ilayer" "$fdir"
        fi
    done
done >"$tmp"

if [ -f "$allow" ]; then
    grep -Fvxf "$allow" "$tmp" >"$tmp.f" 2>/dev/null || true
    mv "$tmp.f" "$tmp"
fi
if [ -s "$tmp" ]; then
    note "FAIL: upward includes found:"
    sed 's/^/    /' "$tmp"
    fail=1
else
    note "ok: no upward includes"
fi

# ---- 2. proto/ symbol hygiene ------------------------------------------
sect "2. proto/ symbol hygiene (nm)"
core_lib="$(find "$build" -name 'libgeryon_core.a' 2>/dev/null | head -1)"
rat_lib="$(find "$build" -name 'libgeryon_ratchet.a' 2>/dev/null | head -1)"
proto_objs="$(find "$build" -path '*geryon_proto*' -name '*.o' 2>/dev/null)"
if [ -z "$core_lib" ] || [ -z "$rat_lib" ] || [ -z "$proto_objs" ]; then
    note "SKIP: build tree not found under $build (configure + build first)"
else
    nm "$core_lib" "$rat_lib" 2>/dev/null |
        awk '$2 ~ /^[TtDdBbRr]$/ {print $3}' | grep -E '^gy_' | sort -u >"$tmp.def"
    # shellcheck disable=SC2086
    nm $proto_objs 2>/dev/null |
        awk '$1 == "U" {print $2}' | grep -E '^gy_' | sort -u >"$tmp.und"
    comm -12 "$tmp.def" "$tmp.und" >"$tmp.viol"
    if [ -s "$tmp.viol" ]; then
        note "FAIL: proto/ references ratchet/core symbols:"
        sed 's/^/    /' "$tmp.viol"
        fail=1
    else
        note "ok: proto/ references no ratchet/core symbol"
    fi
    rm -f "$tmp.def" "$tmp.und" "$tmp.viol"
fi

# ---- 3. C++ standalone compile -----------------------------------------
sect "3. geryon.h standalone C++ compile"
if command -v g++ >/dev/null 2>&1; then
    if g++ -std=c++17 -fsyntax-only -x c++ -Wall -Wextra \
        "$root/include/geryon.h" 2>"$tmp.cpp"; then
        note "ok: geryon.h parses as C++"
    else
        note "FAIL: geryon.h does not compile as C++:"
        sed 's/^/    /' "$tmp.cpp"
        fail=1
    fi
    rm -f "$tmp.cpp"
else
    note "SKIP: g++ not available"
fi

sect "result"
[ "$fail" -eq 0 ] && note PASS || note FAIL
rm -f "$tmp"
exit "$fail"
