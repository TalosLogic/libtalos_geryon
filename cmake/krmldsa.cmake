# KR-ML-DSA backends (QSPGS, docs/plans/QSPGS_DESIGN.md).
#
# src/core/krmldsa/krmldsa_impl.c composes [CFG+] key rerandomization over
# liboqs' mldsa-native INTERNALS.  liboqs compiles that implementation once per
# backend directory (ref / x86_64 / aarch64) under a distinct namespace prefix,
# so the KR source is compiled the same way: once per backend, with the SAME
# -DMLD_CONFIG_PARAMETER_SET / -DMLD_CONFIG_FILE / target flags liboqs used for
# that directory (third_party/liboqs/src/sig/ml_dsa/CMakeLists.txt).  Struct
# layouts and symbol names then match the archive exactly; the dispatchers in
# src/core/krmldsa44.c / krmldsa87.c pick one backend at runtime with liboqs'
# own CPU probe.
#
# The impl lives in a subdirectory so the src/core/*.c glob does not compile it
# without these flags.  Which backends exist follows GERYON_OQS_DIST exactly as
# LIBOQS_BACKEND_ARGS does above: OFF = ref only; ON = ref + host-arch native.
#
# Requires LIBOQS_SOURCE_DIR, LIBOQS_INCLUDE_DIR, liboqs_build, GERYON_WARNINGS.

set(GERYON_KRMLDSA_IMPL "${CMAKE_CURRENT_SOURCE_DIR}/src/core/krmldsa/krmldsa_impl.c")
set(GERYON_KRMLDSA_OBJECTS "")

# liboqs 0.16.0 INSTALLS only the public *_ops.h SHA-3 headers; the internal
# <oqs/sha3.h> / <oqs/sha3x4.h> that the pqclean_shims fips202 glue includes
# exist only in the liboqs BUILD tree's include/ directory.  The KR glue
# reaches SHAKE through that glue (exactly as mldsa-native does inside
# liboqs), so it needs the build-tree include dir in addition to the install
# dir.  Both are static-archive-internal: nothing propagates above Layer 1.
ExternalProject_Get_Property(liboqs_build BINARY_DIR)
set(GERYON_LIBOQS_BUILD_INCLUDE_DIR "${BINARY_DIR}/include")
unset(BINARY_DIR)

# geryon_add_krmldsa_backend(<set> <dir> <token> <config> [extra flags...])
#   set     44 | 87                          (MLD_CONFIG_PARAMETER_SET)
#   dir     ref | x86_64 | aarch64           (mldsa-native_ml-dsa-<set>_<dir>)
#   token   c | x86_64 | aarch64             (GY_KR_BACKEND symbol suffix)
#   config  config_c.h | config_x86_64.h | config_aarch64.h
function(geryon_add_krmldsa_backend set dir token config)
    set(_tgt "geryon_krmldsa_${set}_${token}")
    set(_root "${LIBOQS_SOURCE_DIR}/src/sig/ml_dsa/mldsa-native_ml-dsa-${set}_${dir}")
    add_library(${_tgt} OBJECT "${GERYON_KRMLDSA_IMPL}")
    target_include_directories(${_tgt} PRIVATE
        "${_root}/mldsa/src"
        "${LIBOQS_SOURCE_DIR}/src/common/pqclean_shims"
        "${LIBOQS_INCLUDE_DIR}"
        "${GERYON_LIBOQS_BUILD_INCLUDE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/core"
    )
    # Same form liboqs uses (target_compile_options, quoted config path):
    # MLD_CONFIG_FILE is resolved relative to mldsa/src/common.h, which is why
    # the ../../integration/liboqs/ prefix is correct from any including TU.
    target_compile_options(${_tgt} PRIVATE
        -DMLD_CONFIG_PARAMETER_SET=${set}
        -DMLD_CONFIG_FILE="../../integration/liboqs/${config}"
        ${ARGN}
    )
    target_compile_definitions(${_tgt} PRIVATE
        GY_PRODUCTION_BUILD
        GY_KR_BACKEND=${token}
    )
    # mldsa-native headers define static inline helpers not every TU uses.
    target_compile_options(${_tgt} PRIVATE ${GERYON_WARNINGS} -Wno-unused-function)
    set_target_properties(${_tgt} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    add_dependencies(${_tgt} liboqs_build)
    set(GERYON_KRMLDSA_OBJECTS ${GERYON_KRMLDSA_OBJECTS}
        $<TARGET_OBJECTS:${_tgt}> PARENT_SCOPE)
endfunction()

foreach(_set 44 87)
    geryon_add_krmldsa_backend(${_set} ref c config_c.h)
    if(GERYON_OQS_DIST)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
            geryon_add_krmldsa_backend(${_set} x86_64 x86_64 config_x86_64.h
                -mavx2 -mbmi2 -mpopcnt)
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
            geryon_add_krmldsa_backend(${_set} aarch64 aarch64 config_aarch64.h)
        endif()
    endif()
endforeach()
