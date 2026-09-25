#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# QSPGS client/server scope audit (QSPGS_SPEC section 7.1): the
# stateless SERVER archive (geryon_qsgroups_server) must carry NO client-only
# symbol and, above all, NO rerandomization internal. The server holds no core
# secret parameter: it never derives a pseudonym key (RandVK / RandSK / rho),
# never touches the key hierarchy (muk / uk / gk / ek / rrs), and never opens an
# ek- or gk-keyed field. Its signature checks are the PUBLIC liboqs verifiers
# reached through the sk-free common layer (geryon_qspgs_internal, qspgs_wire.c),
# under a full vkpsdn the member supplies; the recompute-from-rrs resolve path is
# client-only.
#
# The split is structural, not documentary. This scans the server archive for
# each forbidden client symbol as BOTH a definition (nm "T", the code being
# present) and an undefined reference (nm "U", a stray call into it). Either is a
# violation. Only geryon_qsgroups_server is scanned; the client (geryon_qspgs)
# legitimately carries all of these.
#
# Usage: nm_scope_qspgs_server.sh <server-archive>
#   Exits nonzero if the server archive defines or references any client symbol.

set -eu

# Rerandomization internals and the recompute-from-rrs verify paths (the core
# concern: no secret pseudonym derivation server-side).
forbidden='gy_qspgs_derive_rho'
forbidden="${forbidden}|gy_qspgs_derive_sk_psdn"
forbidden="${forbidden}|gy_qspgs_derive_vk_psdn"
forbidden="${forbidden}|gy_qspgs_core_resolve_verify"
forbidden="${forbidden}|gy_qspgs_apx_line_resolve_verify"
# Key hierarchy (muk / uk / acq / expKey / sub-key / base pair).
forbidden="${forbidden}|gy_qspgs_derive_uk"
forbidden="${forbidden}|gy_qspgs_derive_acq"
forbidden="${forbidden}|gy_qspgs_derive_exp_key"
forbidden="${forbidden}|gy_qspgs_derive_sub_key"
forbidden="${forbidden}|gy_qspgs_base_keygen"
forbidden="${forbidden}|gy_qspgs_base_keygen_seed"
forbidden="${forbidden}|gy_qspgs_group_key_gen"
# ek- / gk-keyed field and join PKE (the server interprets no ciphertext).
forbidden="${forbidden}|gy_qspgs_field_seal"
forbidden="${forbidden}|gy_qspgs_field_open"
forbidden="${forbidden}|gy_qspgs_member_ct_seal"
forbidden="${forbidden}|gy_qspgs_member_ct_open"
forbidden="${forbidden}|gy_qspgs_joinlink_seal"
forbidden="${forbidden}|gy_qspgs_joinlink_open"
forbidden="${forbidden}|gy_qspgs_join_derive"
forbidden="${forbidden}|gy_qspgs_join_seal"
forbidden="${forbidden}|gy_qspgs_join_open"
# Client edit / registration / attribution surface.
forbidden="${forbidden}|gy_qspgs_member_build"
forbidden="${forbidden}|gy_qspgs_core_sign"
forbidden="${forbidden}|gy_qspgs_apx_line_sign"
forbidden="${forbidden}|gy_qspgs_member_decrypt"
forbidden="${forbidden}|gy_qspgs_attribute_hash"
forbidden="${forbidden}|gy_qspgs_register"
forbidden="${forbidden}|gy_qspgs_acct_verify"
forbidden="${forbidden}|gy_qspgs_invite_seal"
forbidden="${forbidden}|gy_qspgs_invite_open"
forbidden="${forbidden}|gy_qspgs_invite_verify"
forbidden="${forbidden}|gy_qspgs_pers_sign"
forbidden="${forbidden}|gy_qspgs_pers_verify"
forbidden="${forbidden}|gy_qspgs_member_ctx_open"

lib="${1:?usage: nm_scope_qspgs_server.sh <server-archive>}"
if [ ! -f "$lib" ]; then
    echo "nm_scope_qspgs_server: missing archive: $lib" >&2
    exit 1
fi

# The symbol name is nm's last field whether the line is a definition
# ("... T sym") or an undefined reference ("... U sym"); either presence in the
# server archive is a violation. Exact-match the last field against the
# forbidden set.
if nm "$lib" 2>/dev/null | awk '{print $NF}' \
    | grep -Ex "(${forbidden})" >/dev/null; then
    echo "nm_scope_qspgs_server: FORBIDDEN client symbol in the SERVER archive" \
        "$(basename "$lib"):" >&2
    nm "$lib" 2>/dev/null | awk '{print $NF}' | grep -Ex "(${forbidden})" >&2
    exit 1
fi

echo "nm_scope_qspgs_server: OK (no client symbols in the server archive)"
exit 0
