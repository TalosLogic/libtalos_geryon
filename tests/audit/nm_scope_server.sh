#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Client/server scope audit (GER-M8-07, GROUP_SPEC section 8.3): the CLIENT
# group archive (geryon_group) must contain NO ServerSecretParams-consuming
# operation - the role split is structural, not documentary. This scans the
# client archive for the server-role symbols as BOTH a definition (nm "T", the
# code being present) and an undefined reference (nm "U", a stray call into it).
# Either is a violation: a client binary must never carry issuance code or a path
# that consumes ServerSecretParams.
#
# The server operations live in geryon_groups_server (a separate target); the
# sk-free shared layer lives in geryon_group_internal. Only geryon_group (client)
# is scanned here.
#
# Usage: nm_scope_server.sh <client-archive>
#   Exits nonzero if the client archive defines or references any server symbol.

set -eu

# The five section 8.1 server operations plus their KAT-only cores: every
# geryon symbol that takes a struct gy_group_server_secret.
forbidden='gy_group_auth_issue'
forbidden="${forbidden}|gy_group_pk_blind_issue"
forbidden="${forbidden}|gy_group_auth_present_verify"
forbidden="${forbidden}|gy_group_pk_present_verify"
forbidden="${forbidden}|gy_group_server_keygen"
forbidden="${forbidden}|gy_group_server_keygen_scalars"
forbidden="${forbidden}|gy_group_server_public_from_secret"
forbidden="${forbidden}|gy_group_mac"
forbidden="${forbidden}|gy_group_mac_tu"
forbidden="${forbidden}|gy_group_verify"
forbidden="${forbidden}|gy_group_server_secret_clear"

lib="${1:?usage: nm_scope_server.sh <client-archive>}"
if [ ! -f "$lib" ]; then
    echo "nm_scope_server: missing archive: $lib" >&2
    exit 1
fi

# The symbol name is nm's last field whether the line is a definition
# ("... T sym") or an undefined reference ("... U sym"); either presence in the
# client archive is a violation. Exact-match the last field against the
# forbidden set so gy_group_verify does not match gy_group_pk_present_verify.
if nm "$lib" 2>/dev/null | awk '{print $NF}' \
    | grep -Ex "(${forbidden})" >/dev/null; then
    echo "nm_scope_server: FORBIDDEN server symbol in the CLIENT archive" \
        "$(basename "$lib"):" >&2
    nm "$lib" 2>/dev/null | awk '{print $NF}' | grep -Ex "(${forbidden})" >&2
    exit 1
fi

echo "nm_scope_server: OK (no server symbols in the client archive)"
exit 0
