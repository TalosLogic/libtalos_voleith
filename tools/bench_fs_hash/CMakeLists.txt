# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Microbenchmark FS-hash candidates (Grøstl-256/512 HW/SW, SHAKE-128/256)
# to inform the Grøstl-FS vs SHAKE selection in
# docs/FS_TRANSFORM_SWITCHING_DESIGN.md.
#
# One source file (bench_fs_hash.c) is compiled six times with different
# VOLEITH_BENCH_HASH selections and against two private core-source
# libraries: one with hardware AES flags applied, one without.  The
# resulting six binaries land in build/tools/bench_fs_hash/.
#
# Build with:
#   cmake -DVOLEITH_BUILD_BENCH=ON ...
# Run each binary directly; redirect to a file for analysis.

# ---- private static libraries: one HW, one SW ----------------------------
#
# Re-anchor VOLEITH_CORE_SOURCES (paths are relative to the top-level
# CMakeLists) so this subdirectory can find them, mirroring the
# tools/dudect pattern.
set(_BENCH_CORE_SOURCES "")
foreach(_src ${VOLEITH_CORE_SOURCES})
    list(APPEND _BENCH_CORE_SOURCES "${CMAKE_SOURCE_DIR}/${_src}")
endforeach()

# HW lib: replicate voleith_apply_hw_flags so Grøstl picks up the AES
# round instructions on whichever ISA is present.
add_library(voleith_core_bench_hw STATIC ${_BENCH_CORE_SOURCES})
target_include_directories(voleith_core_bench_hw
    PUBLIC ${VOLEITH_CORE_INCLUDES}
)
if(HAVE_CLMUL)
    target_compile_definitions(voleith_core_bench_hw PUBLIC VOLEITH_HAVE_CLMUL)
    target_compile_options(voleith_core_bench_hw PRIVATE -mpclmul -msse2 -msse4.1)
endif()
if(HAVE_AES_NI)
    target_compile_definitions(voleith_core_bench_hw PUBLIC VOLEITH_HAVE_AES_NI)
    target_compile_options(voleith_core_bench_hw PRIVATE -maes -msse2 -mssse3)
endif()
if(HAVE_ARMV8_AES)
    target_compile_definitions(voleith_core_bench_hw PUBLIC VOLEITH_HAVE_ARMV8_AES)
    if(ARMV8_CRYPTO_FLAGS)
        target_compile_options(voleith_core_bench_hw PRIVATE ${ARMV8_CRYPTO_FLAGS})
    endif()
endif()
if(HAVE_PMULL)
    target_compile_definitions(voleith_core_bench_hw PUBLIC VOLEITH_HAVE_PMULL)
    if(ARMV8_CRYPTO_FLAGS AND NOT HAVE_ARMV8_AES)
        target_compile_options(voleith_core_bench_hw PRIVATE ${ARMV8_CRYPTO_FLAGS})
    endif()
endif()

# SW lib: no hardware flags.  Forces Grøstl through the bitsliced AES
# S-box path in core/aes_ct64.c, which is the relevant comparison for
# targets without hardware AES (per the project's fallback-validation
# standard, the SW path is a production deployment on those targets).
add_library(voleith_core_bench_sw STATIC ${_BENCH_CORE_SOURCES})
target_include_directories(voleith_core_bench_sw
    PUBLIC ${VOLEITH_CORE_INCLUDES}
)

unset(_BENCH_CORE_SOURCES)

# ---- binaries -------------------------------------------------------------
#
# Each binary is one (hash, lib) pair.  HW/SW for SHAKE is meaningless
# (no SHA-3 ISA path in core/hash.c), so we only build one SHAKE binary
# per security level, linked against the HW lib for parity with the
# Grøstl-HW link line.

function(voleith_bench_add NAME HASH_KIND LIB)
    add_executable(${NAME} bench_fs_hash.c)
    target_compile_definitions(${NAME} PRIVATE VOLEITH_BENCH_HASH=${HASH_KIND})
    # Pull in bench_util.h from examples/ rather than duplicating.
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/examples
    )
    target_link_libraries(${NAME} PRIVATE ${LIB})
    set_target_properties(${NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools/bench_fs_hash
    )
endfunction()

# Grøstl: build both HW and SW.  HW binaries are skipped if no AES-NI /
# ARMv8-AES was detected on the host (the lib would still build but the
# resulting "HW" binary would silently take the SW path, polluting the
# comparison).
set(_BENCH_HW_AVAILABLE FALSE)
if(HAVE_AES_NI OR HAVE_ARMV8_AES)
    set(_BENCH_HW_AVAILABLE TRUE)
endif()

if(_BENCH_HW_AVAILABLE)
    voleith_bench_add(bench_grostl256_hw GROSTL256 voleith_core_bench_hw)
    voleith_bench_add(bench_grostl512_hw GROSTL512 voleith_core_bench_hw)
else()
    message(STATUS
        "voleith bench: skipping *_hw Grøstl binaries (no AES-NI / ARMv8-AES detected)")
endif()

voleith_bench_add(bench_grostl256_sw GROSTL256 voleith_core_bench_sw)
voleith_bench_add(bench_grostl512_sw GROSTL512 voleith_core_bench_sw)

voleith_bench_add(bench_shake128 SHAKE128 voleith_core_bench_hw)
voleith_bench_add(bench_shake256 SHAKE256 voleith_core_bench_hw)
