#!/usr/bin/env python3
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Independent verify-equation oracle for geryon's classical group KVAC/NIZK
# layer (GROUP_SPEC sections 5.1-5.3, GER-M8-04/05 task 5, D-GEN-6), BOTH tiers.
#
# geryon's group proofs are clean-room and DELIBERATELY not zkgroup-byte-
# compatible (D-GRP-4), so no zkgroup/poksho byte-compat or interop cross-check
# is possible and D-GEN-6 forbids a compat parameterization.  This is instead an
# INDEPENDENT reimplementation, from the [CPZ] paper and GROUP_SPEC only, of
#
#   (1) the sound-conjunction Fiat-Shamir transcript, and
#   (2) the per-equation verify relation  V[j] == sum_{i active} G[j][i]^r_i
#       + c * P[j],
#
# reconstructing each proof's equation LAYOUT itself (which generator sits in
# which witness slot, and how each target is formed), so a wrong-generator-in-
# slot or wrong target in geryon's assembly fails here even though it verifies
# against geryon's own matrix.
#
# The independence is at the PROTOCOL layer.  The group arithmetic is a shared
# primitive (as in geryon), validated separately (RFC 9496 for ristretto255,
# RFC 7748/8032 / the libdecaf gate for decaf448):
#
#   255 tier: libsodium ristretto255 (ctypes).  Challenge SHA-512 -> reduce.
#   448 tier: geryon's vendored libdecaf via the decaf448_shim shared lib.
#             Challenge SHAKE256 (114-byte squeeze) -> decode_long.  The two
#             tiers' transcripts differ in hash, width, and reduction; this
#             oracle validates the 448 transcript independently, which no 255
#             check and no round-trip (shared prover/verifier) can.
#
# Usage:  python3 verify.py [--decaf448 PATH] <group_kvac.vec>
#   --decaf448 PATH   path to the decaf448_shim shared library (or set env
#                     GROUP_KVAC_DECAF448).  Without it, 448 records are SKIPPED.
# Exit 0 if every verified equation holds; 1 on any mismatch; 2 if nothing could
# be verified (no usable backend).

import ctypes
import ctypes.util
import hashlib
import os
import sys

IDENTITY255 = b"\x00" * 32


# --- 255 backend: libsodium ristretto255 ------------------------------------

class Ristretto255Backend:
    W = 32

    def __init__(self):
        name = (ctypes.util.find_library("sodium")
                or ctypes.util.find_library("libsodium"))
        lib = None
        if name:
            try:
                lib = ctypes.CDLL(name)
            except OSError:
                lib = None
        if lib is None:
            for cand in ("libsodium.so.23", "libsodium.so", "libsodium.dylib"):
                try:
                    lib = ctypes.CDLL(cand)
                    break
                except OSError:
                    continue
        if lib is None or lib.sodium_init() < 0:
            raise RuntimeError("libsodium not available")
        self.s = lib

    def identity(self):
        return IDENTITY255

    def smul(self, scalar, point):
        out = ctypes.create_string_buffer(32)
        if self.s.crypto_scalarmult_ristretto255(out, scalar, point) != 0:
            return IDENTITY255          # libsodium returns -1 on identity result
        return out.raw[:32]

    def add(self, p, q):
        out = ctypes.create_string_buffer(32)
        if self.s.crypto_core_ristretto255_add(out, p, q) != 0:
            raise ValueError("ristretto255_add failed")
        return out.raw[:32]

    def sub(self, p, q):
        out = ctypes.create_string_buffer(32)
        if self.s.crypto_core_ristretto255_sub(out, p, q) != 0:
            raise ValueError("ristretto255_sub failed")
        return out.raw[:32]

    def neg(self, p):
        return self.sub(self.identity(), p)

    def challenge(self, transcript):
        wide = hashlib.sha512(transcript).digest()          # 64 bytes
        out = ctypes.create_string_buffer(32)
        self.s.crypto_core_ristretto255_scalar_reduce(out, wide)
        return out.raw[:32]


# --- 448 backend: libdecaf via the decaf448_shim shared lib -----------------

class Decaf448Backend:
    W = 56

    def __init__(self, shim_path):
        lib = ctypes.CDLL(shim_path)
        for fn in ("gk448_scalarmul", "gk448_add", "gk448_sub"):
            getattr(lib, fn).restype = ctypes.c_int
        lib.gk448_challenge_reduce.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong]
        self.l = lib
        self._identity = self._call0(lib.gk448_identity)

    def _call0(self, fn):
        out = ctypes.create_string_buffer(56)
        fn(out)
        return out.raw[:56]

    def identity(self):
        return self._identity

    def basepoint(self):
        return self._call0(self.l.gk448_basepoint)

    def _binop(self, fn, a, b):
        out = ctypes.create_string_buffer(56)
        if fn(out, a, b) != 0:
            raise ValueError("decaf448 op failed (invalid point)")
        return out.raw[:56]

    def smul(self, scalar, point):
        return self._binop(self.l.gk448_scalarmul, scalar, point)

    def add(self, p, q):
        return self._binop(self.l.gk448_add, p, q)

    def sub(self, p, q):
        return self._binop(self.l.gk448_sub, p, q)

    def neg(self, p):
        return self.sub(self.identity(), p)

    def challenge(self, transcript):
        wide = hashlib.shake_256(transcript).digest(114)    # 114-byte squeeze
        out = ctypes.create_string_buffer(56)
        self.l.gk448_challenge_reduce(out, wide, ctypes.c_ulong(len(wide)))
        return out.raw[:56]


# --- NUMS generator ordinals (must match group_params.h GY_GEN_*) -----------

(W, WPRIME, X0, X1, Y1, Y2, Y3, Y4, M1G, M2G, M3G, M4G, V, A1, A2, B1, B2,
 J1, J2, J3) = range(20)

# --- Proof layouts, reconstructed independently from GROUP_SPEC -------------
# Atoms: ("g", idx) generator; ("p", name) named point; ("neg", atom);
#        ("sub", a, b); ("ut",) t*U; ("Z", "pi_a"/"pi_p") secret-derived target.

LAYOUTS = {
    "pi_I": {
        "eqs": [
            ({0: ("g", W), 1: ("g", WPRIME)}, ("p", "C_W")),
            ({2: ("g", X0), 3: ("g", X1), 4: ("g", Y1), 5: ("g", Y2),
              6: ("g", Y3)}, ("sub", ("g", V), ("p", "I"))),
            ({0: ("g", W), 2: ("p", "U"), 3: ("ut",), 4: ("p", "M1"),
              5: ("p", "M2"), 6: ("p", "M3")}, ("p", "Vtag")),
        ],
    },
    "pi_A": {
        "eqs": [
            ({0: ("p", "I")}, ("Z", "pi_a")),
            ({5: ("p", "C_x0"), 3: ("g", X0), 0: ("g", X1)}, ("p", "C_x1")),
            ({1: ("g", A1), 2: ("g", A2)}, ("p", "A")),
            ({0: ("g", Y2), 2: ("neg", ("p", "E_A1"))},
             ("sub", ("p", "C_y2"), ("p", "E_A2"))),
            ({1: ("p", "C_y1"), 4: ("g", Y1)}, ("p", "E_A1")),
            ({0: ("g", Y3)}, ("p", "C_y3")),
        ],
    },
    "pi_P": {
        "eqs": [
            ({0: ("p", "I")}, ("Z", "pi_p")),
            ({8: ("p", "C_x0"), 5: ("g", X0), 0: ("g", X1)}, ("p", "C_x1")),
            ({1: ("g", A1), 2: ("g", A2)}, ("p", "A")),
            ({3: ("g", B1), 4: ("g", B2)}, ("p", "B")),
            ({0: ("g", Y2), 2: ("neg", ("p", "E_A1"))},
             ("sub", ("p", "C_y2"), ("p", "E_A2"))),
            ({1: ("p", "C_y1"), 6: ("g", Y1)}, ("p", "E_A1")),
            ({0: ("g", Y4), 4: ("neg", ("p", "E_B1"))},
             ("sub", ("p", "C_y4"), ("p", "E_B2"))),
            ({3: ("p", "C_y3"), 7: ("g", Y3)}, ("p", "E_B1")),
        ],
    },
    "pi_BR": {
        "eqs": [
            ({0: ("p", "Gbase")}, ("p", "Y")),
            ({1: ("p", "Gbase")}, ("p", "D1")),
            ({2: ("p", "Gbase")}, ("p", "E1")),
            ({3: ("g", J3)}, ("p", "J3")),
            ({1: ("p", "Y"), 3: ("neg", ("g", J1))},
             ("sub", ("p", "D2"), ("p", "J1"))),
            ({2: ("p", "Y"), 3: ("neg", ("g", J2))},
             ("sub", ("p", "E2"), ("p", "J2"))),
        ],
    },
    "pi_BI": {
        "eqs": [
            ({0: ("g", W), 1: ("g", WPRIME)}, ("p", "C_W")),
            ({6: ("g", X0), 7: ("g", X1), 2: ("g", Y1), 3: ("g", Y2),
              4: ("g", Y3), 5: ("g", Y4)}, ("sub", ("g", V), ("p", "I"))),
            ({4: ("p", "D1"), 5: ("p", "E1"), 8: ("p", "Gbase")}, ("p", "S1")),
            ({4: ("p", "D2"), 5: ("p", "E2"), 8: ("p", "Y"), 0: ("g", W),
              6: ("p", "U"), 7: ("ut",), 2: ("p", "M1"), 3: ("p", "M2")},
             ("p", "S2")),
        ],
    },
}


def be32(n):
    return n.to_bytes(4, "big")


def eval_atom(atom, rec, gens, be):
    kind = atom[0]
    if kind == "g":
        return gens[atom[1]]
    if kind == "p":
        return rec[atom[1]]
    if kind == "neg":
        return be.neg(eval_atom(atom[1], rec, gens, be))
    if kind == "sub":
        return be.sub(eval_atom(atom[1], rec, gens, be),
                      eval_atom(atom[2], rec, gens, be))
    if kind == "ut":
        return be.smul(rec["t"], rec["U"])
    if kind == "Z":
        return reconstruct_Z(atom[1], rec, be)
    raise ValueError("bad atom %r" % (atom,))


def reconstruct_Z(which, rec, be):
    # Independent [CPZ] section 5.2 verifier recomputation of the eq0 target Z
    # from the (test) server secret and the presentation commitments:
    #   Z = C_V - (W + x0 C_x0 + x1 C_x1 + y1 C_y1 + y2 C_y2 + ...).
    d = rec["sk_W"]
    d = be.add(d, be.smul(rec["sk_x0"], rec["C_x0"]))
    d = be.add(d, be.smul(rec["sk_x1"], rec["C_x1"]))
    d = be.add(d, be.smul(rec["sk_y1"], rec["C_y1"]))
    d = be.add(d, be.smul(rec["sk_y2"], rec["C_y2"]))
    if which == "pi_a":
        cy3m3 = be.add(rec["C_y3"], rec["M3"])       # fold revealed m3 into y3
        d = be.add(d, be.smul(rec["sk_y3"], cy3m3))
    else:  # pi_p
        d = be.add(d, be.smul(rec["sk_y3"], rec["C_y3"]))
        d = be.add(d, be.smul(rec["sk_y4"], rec["C_y4"]))
    return be.sub(rec["C_V"], d)


def build_statement(rec, gens, be):
    layout = LAYOUTS[rec["proof"]]
    k, m, max_k = rec["k"], rec["m"], rec["max_k"]
    mask = [[0] * max_k for _ in range(m)]
    gm = [[None] * k for _ in range(m)]
    P = [None] * m
    for j, (slots, target) in enumerate(layout["eqs"]):
        for i, atom in slots.items():
            mask[j][i] = 1
            gm[j][i] = eval_atom(atom, rec, gens, be)
        P[j] = eval_atom(target, rec, gens, be)
    return k, m, max_k, mask, gm, P


def compute_challenge(rec, be, k, m, max_k, mask, gm, P, Vc):
    w = be.W
    h = be32(k) + be32(m)
    h += be32(m * max_k)
    for j in range(m):
        h += bytes(mask[j])                          # max_k mask bytes per row
    for j in range(m):
        for i in range(k):
            if mask[j][i]:
                h += be32(w) + gm[j][i]              # active generators only
    for j in range(m):
        h += be32(w) + Vc[j]                         # commitments
    for j in range(m):
        h += be32(w) + P[j]                          # targets
    uid = rec["user_id"]
    h += be32(len(uid)) + uid
    oi = rec.get("other_info", b"")
    if oi:
        h += be32(len(oi)) + oi
    return be.challenge(h)


def verify_record(rec, be):
    proof = rec["proof"]
    if proof not in LAYOUTS:
        return False, "unknown proof %s" % proof
    gens = [rec["g%d" % i] for i in range(20)]
    k, m, max_k, mask, gm, P = build_statement(rec, gens, be)
    Vc = [rec["Vc%d" % j] for j in range(m)]
    r = [rec["r%d" % i] for i in range(k)]
    c = compute_challenge(rec, be, k, m, max_k, mask, gm, P, Vc)
    for j in range(m):
        lhs = be.identity()
        for i in range(k):
            if mask[j][i]:
                lhs = be.add(lhs, be.smul(r[i], gm[j][i]))
        rhs = be.add(lhs, be.smul(c, P[j]))
        if rhs != Vc[j]:
            return False, "equation %d mismatch" % j
    return True, "%d equations" % m


# --- vector-file parsing ----------------------------------------------------

def parse_records(path):
    recs, cur = [], {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                if cur:
                    recs.append(cur)
                    cur = {}
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if key == "proof":
                cur[key] = val
            elif key in ("k", "m", "max_k", "tier"):
                cur[key] = int(val)
            else:
                cur[key] = bytes.fromhex(val)
    if cur:
        recs.append(cur)
    return recs


def main():
    args = sys.argv[1:]
    shim = os.environ.get("GROUP_KVAC_DECAF448")
    path = None
    i = 0
    while i < len(args):
        if args[i] == "--decaf448" and i + 1 < len(args):
            shim = args[i + 1]
            i += 2
        else:
            path = args[i]
            i += 1
    if path is None:
        sys.stderr.write("usage: verify.py [--decaf448 PATH] <group_kvac.vec>\n")
        return 2

    try:
        recs = parse_records(path)
    except OSError as e:
        sys.stderr.write("group_kvac oracle: %s\n" % e)
        return 2
    if not recs:
        sys.stderr.write("group_kvac oracle: no records.\n")
        return 2

    # Lazily build backends; a missing one skips its tier rather than failing.
    backends, errors = {}, {}
    try:
        backends[255] = Ristretto255Backend()
    except Exception as e:
        errors[255] = str(e)
    if shim:
        try:
            backends[448] = Decaf448Backend(shim)
        except Exception as e:
            errors[448] = "decaf448 shim load failed: %s" % e
    else:
        errors[448] = "no --decaf448 shim (env GROUP_KVAC_DECAF448 unset)"

    failures = verified = skipped = 0
    for rec in recs:
        proof = rec.get("proof", "?")
        tier = rec.get("tier", 255)
        be = backends.get(tier)
        if be is None:
            print("%-6s SKIP  (tier %d: %s)" % (proof, tier,
                                                errors.get(tier, "no backend")))
            skipped += 1
            continue
        try:
            ok, detail = verify_record(rec, be)
        except Exception as e:
            ok, detail = False, "error: %s" % e
        print("%-6s %-4s (tier %d, %s)" % (
            proof, "PASS" if ok else "FAIL", tier, detail))
        if ok:
            verified += 1
        else:
            failures += 1

    print("\n%d records: %d verified, %d failed, %d skipped"
          % (len(recs), verified, failures, skipped))
    if failures:
        return 1
    if verified == 0:
        sys.stderr.write("group_kvac oracle: no records verified "
                         "(no usable backend).\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
