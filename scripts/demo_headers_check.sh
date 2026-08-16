#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Build-hygiene check: the end-to-end example must depend on the
# public surface only.  Fail if any examples/ source includes a local header
# ("...") other than geryon.h or the demo's own headers - in particular, no
# internal library header (envelope.h, custodian.h, facade.h, ...).  System
# includes (<...>) are ignored.
#
# Usage: scripts/demo_headers_check.sh [examples-dir]

set -eu

dir="${1:-$(CDPATH= cd -- "$(dirname -- "$0")/../examples" && pwd)}"

allow='geryon\.h|client\.h|coordinator\.h|demo_ipc\.h|demo_proto\.h|filestore\.h'

bad=$(grep -rhoE '#include "[^"]+"' "$dir"/*.c "$dir"/*.h 2>/dev/null |
    sed -e 's/#include "//' -e 's/"$//' |
    sort -u |
    grep -vE "^($allow)$" || true)

if [ -n "$bad" ]; then
    echo "demo include check FAILED: forbidden local includes:" >&2
    echo "$bad" >&2
    exit 1
fi

echo "demo include check OK: examples use only geryon.h + demo-local headers"
