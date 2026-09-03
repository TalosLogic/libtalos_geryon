#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Dependency-surface audit: geryon's own objects must reference NO
# C++ runtime (libstdc++/libsupc++) and NO OpenSSL.  The sanctioned runtime
# providers are libsodium (crypto_*/sodium_*), liboqs (OQS_*, the four PQ
# algorithms only), libdecaf (the vendored 448 curve slice, decaf_*/gf_*), and
# monocypher, plus libc/libm.  The 448 curve provider was direct-compiled as C
# precisely so no C++ runtime is linked; this gate keeps that true
# across all four suites' worth of objects, and catches OpenSSL creeping in
# (e.g. a liboqs built against it) in a fully linked binary.
#
# Usage: dependency_surface.sh <path> [<path> ...]
#   Each path is a geryon static archive (.a) or a linked ELF binary.  Every
#   path is nm-scanned for an UNDEFINED reference to a forbidden namespace; any
#   path that ldd accepts (a linked binary) is additionally checked for a
#   forbidden shared object in its dynamic dependencies.  Exits nonzero on any
#   violation.

set -eu

# C++ Itanium ABI / libstdc++ entry points, and OpenSSL entry points.  geryon is
# clean-room C17 over libsodium/liboqs/libdecaf/monocypher; an undefined ref to
# any of these means a stray dependency crept into geryon's own code.
cxx='^(__cxa_|__cxxabiv|_ZSt|_ZNSt|_ZNKSt|_ZTVSt|_Znwm|_Znam|_ZdlPv|_ZdaPv|__gxx_)'
ossl='^(SSL_|X509_|EVP_|BIO_|OPENSSL_|ERR_get|RAND_bytes|i2d_|d2i_)'

status=0

for p in "$@"; do
    if [ ! -f "$p" ]; then
        echo "dependency_surface: missing path: $p" >&2
        exit 1
    fi

    # Undefined references only (nm marks them " U <sym>"); reduce to the symbol.
    undef=$(nm "$p" 2>/dev/null | sed -n 's/^ *U //p' || true)

    chits=$(printf '%s\n' "$undef" | grep -E "$cxx" || true)
    if [ -n "$chits" ]; then
        echo "dependency_surface: C++ runtime reference in $(basename "$p"):" >&2
        printf '  %s\n' $chits >&2
        status=1
    fi

    ohits=$(printf '%s\n' "$undef" | grep -E "$ossl" || true)
    if [ -n "$ohits" ]; then
        echo "dependency_surface: OpenSSL reference in $(basename "$p"):" >&2
        printf '  %s\n' $ohits >&2
        status=1
    fi

    # A fully linked binary's dynamic dependencies must carry no C++ runtime or
    # OpenSSL shared object.  ldd fails harmlessly on a static archive (skip).
    if command -v ldd >/dev/null 2>&1; then
        bad=$(ldd "$p" 2>/dev/null |
            grep -Ei 'libstdc\+\+|libc\+\+|libsupc\+\+|libssl|libcrypto' || true)
        if [ -n "$bad" ]; then
            echo "dependency_surface: forbidden shared object linked into" \
                "$(basename "$p"):" >&2
            printf '  %s\n' "$bad" >&2
            status=1
        fi
    fi
done

if [ "$status" -eq 0 ]; then
    echo "dependency_surface: OK (geryon objects carry no C++ runtime or OpenSSL"
    echo "  reference, and no forbidden shared object is linked; providers are"
    echo "  libsodium, liboqs, libdecaf, monocypher, libc/libm)"
fi
exit "$status"
