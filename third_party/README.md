# Third-party dependencies

All vendored dependencies are under permissive licenses compatible with
redistribution (see docs/DESIGN.md, Licensing). Each retains its upstream
LICENSE file intact. Copyleft code (e.g. libsignal) is NEVER vendored here; it
is used only as an out-of-tree test-oracle generator (docs/TEST_ORACLES.md).

| Dependency | Path | License | Pin | Upstream |
|------------|------|---------|-----|----------|
| libsodium | `libsodium/` | ISC | 1.0.22 | https://github.com/jedisct1/libsodium |
| liboqs | `liboqs/` | MIT | 0.16.0 | https://github.com/open-quantum-safe/liboqs |
| monocypher | `monocypher/` | BSD-2-Clause / CC0 | 4.0.3 | https://github.com/LoupVaillant/Monocypher |
| ed448goldilocks (libdecaf) | `ed448goldilocks-code/` | MIT | v1.0.3 (e5cc6240690d3ffdfcbdb1e4e851954b789cd5d9) | https://sourceforge.net/p/ed448goldilocks/code |

## ed448goldilocks / libdecaf (X448 + XEd448 provider, M6 / c448 tier)

Provides the 448-bit field, scalar, and point arithmetic for the geryon_c448
and geryon_h448_1024 suites (D-XED-9). A git submodule at
`third_party/ed448goldilocks-code`, pinned to tag v1.0.3.

Integration is DIRECT compilation of the 448 C-source slice, not
`add_subdirectory` and not ExternalProject (D-XED-12 Build, amended 2026-08-20;
GER-M6-02). Rationale: libdecaf's top-level `project(DECAF ... LANGUAGES C CXX)`
would drag a C++ toolchain into geryon's build under either of those mechanisms
even though zero C++ is compiled into the static library, and geryon links NO
C++ runtime (`libstdc++`) at runtime by policy. geryon therefore compiles only
libdecaf's C sources for the 448 path (into the `decaf448` static archive) and
runs libdecaf's Python code generator via CMake custom commands. See
`CMakeLists.txt` (the "libdecaf / ed448goldilocks" section) and
docs/decisions/xeddsa.md D-XED-12/13.

The RFC 8032 Ed448 scheme functions (`decaf_ed448_sign` / `decaf_ed448_verify`)
compute a DIFFERENT signature scheme than XEd448 and are called ONLY by the 448
validation-gate tests; geryon's own code never references them (nm scope check,
GER-M6-02).
